#!/usr/bin/env python3
"""Sysmon: lightweight Unix system monitor with persistent outbound traffic accounting."""

import argparse
try:
    import curses
except ImportError:
    curses = None
import datetime
import fcntl
import json
import os
import re
import shutil
import subprocess
import socket
import sys
import tempfile
import time
from pathlib import Path

import psutil

VERSION = "0.2.0-dev"
BOX_WIDTH = 70
DEFAULT_PERIODS = ("today", "7d", "30d", "all")
PERIOD_LABELS = {
    "today": "Today",
    "7d": "7 Days",
    "30d": "30 Days",
    "all": "All Time",
}
DATA_DIR = Path(os.environ.get("SYSMON_DATA_DIR", "/var/lib/sysmon"))
DATA_FILE = Path(os.environ.get("SYSMON_DATA_FILE", str(DATA_DIR / "traffic.json")))
LOCK_FILE = Path(os.environ.get("SYSMON_LOCK_FILE", str(DATA_DIR / "traffic.lock")))


class SysmonError(Exception):
    """An expected application or configuration error."""


def boot_marker():
    """Return a cross-platform marker that changes after an operating-system reboot."""
    return int(psutil.boot_time())


def run_command(command):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout
    except (OSError, ValueError):
        pass
    return ""


def linux_default_interface():
    """Read the preferred default route without requiring a network utility."""
    ip_path = shutil.which("ip")
    if ip_path:
        output = run_command([ip_path, "-o", "route", "show", "default"])
        candidates = []
        for line in output.splitlines():
            fields = line.split()
            if "dev" in fields:
                try:
                    interface = fields[fields.index("dev") + 1]
                    metric = int(fields[fields.index("metric") + 1]) if "metric" in fields else 0
                    candidates.append((metric, interface))
                except (ValueError, IndexError):
                    continue
        if candidates:
            candidates.sort(key=lambda item: item[0])
            return candidates[0][1]

    route_file = Path("/proc/net/route")
    try:
        with route_file.open("r", encoding="ascii") as stream:
            next(stream, None)
            candidates = []
            for line in stream:
                fields = line.split()
                if len(fields) < 8 or fields[1] != "00000000":
                    continue
                try:
                    flags = int(fields[3], 16)
                    metric = int(fields[6])
                except ValueError:
                    continue
                if flags & 0x1:
                    candidates.append((metric, fields[0]))
            if candidates:
                candidates.sort(key=lambda item: item[0])
                return candidates[0][1]
    except (OSError, StopIteration):
        pass

    # IPv6-only Linux hosts expose default routes in /proc/net/ipv6_route.
    ipv6_route_file = Path("/proc/net/ipv6_route")
    try:
        candidates = []
        with ipv6_route_file.open("r", encoding="ascii") as stream:
            for line in stream:
                fields = line.split()
                if len(fields) < 10 or fields[0] != ("0" * 32) or fields[1] != "00":
                    continue
                try:
                    metric = int(fields[5], 16)
                    flags = int(fields[8], 16)
                except ValueError:
                    continue
                if flags & 0x1:
                    candidates.append((metric, fields[9]))
        if candidates:
            candidates.sort(key=lambda item: item[0])
            return candidates[0][1]
    except OSError:
        pass
    return None


def bsd_default_interface():
    route_path = shutil.which("route")
    if not route_path:
        return None
    for arguments in (("-n", "get", "default"), ("-n", "get", "-inet6", "default")):
        output = run_command([route_path] + list(arguments))
        for line in output.splitlines():
            match = re.match(r"\s*(?:interface|dev)\s*:\s*(\S+)", line, re.IGNORECASE)
            if match:
                return match.group(1)
    return None


def is_virtual_interface(name):
    """Identify common tunnel, loopback, bridge and container interface names."""
    lowered = name.lower()
    excluded_prefixes = (
        "lo", "tun", "tap", "wg", "docker", "br", "veth", "virbr",
        "vmnet", "vboxnet", "utun", "gif", "pflog", "ppp", "tailscale", "zt",
        "sit", "ip6tnl", "ifb",
    )
    return lowered.startswith(excluded_prefixes)


def fallback_interface(counters):
    """Use a sole active, addressed non-loopback NIC; never guess among several NICs."""
    stats = psutil.net_if_stats() or {}
    addrs = psutil.net_if_addrs() or {}
    candidates = []
    for name in counters:
        if is_virtual_interface(name):
            continue
        info = stats.get(name)
        if info is not None and not info.isup:
            continue
        has_ip_address = any(
            address.family in (socket.AF_INET, socket.AF_INET6)
            for address in addrs.get(name, [])
        )
        if has_ip_address:
            candidates.append(name)
    if len(candidates) == 1:
        return candidates[0]
    return None


def detect_interface(counters):
    system = sys.platform.lower()
    interface = None
    if system.startswith("linux"):
        interface = linux_default_interface()
    elif system.startswith(("freebsd", "openbsd", "netbsd")):
        interface = bsd_default_interface()
    if interface in counters and not is_virtual_interface(interface):
        return interface
    return fallback_interface(counters)


def empty_state():
    return {
        "version": 1,
        "created_at": int(time.time()),
        "interface": None,
        "last_counter": None,
        "last_sample": None,
        "boot_marker": boot_marker(),
        "daily": {},
        "settings": {
            "interface": "auto",
            "limit_bytes": None,
            "quota_start_date": datetime.date.today().isoformat(),
            "setup_complete": False,
        },
        "notes": [],
    }


def load_state():
    if not DATA_FILE.exists():
        return None
    try:
        with DATA_FILE.open("r", encoding="utf-8") as stream:
            state = json.load(stream)
    except (OSError, ValueError) as exc:
        raise SysmonError("traffic.json is unreadable or damaged: {}".format(exc))
    if not isinstance(state, dict) or state.get("version") != 1:
        raise SysmonError("Unsupported traffic.json format version")
    if not isinstance(state.get("daily"), dict) or not isinstance(state.get("settings"), dict):
        raise SysmonError("traffic.json has an invalid structure")
    state.setdefault("notes", [])
    state["settings"].setdefault("interface", "auto")
    state["settings"].setdefault("limit_bytes", None)
    state["settings"].setdefault(
        "quota_start_date",
        datetime.date.fromtimestamp(int(state.get("created_at", time.time()))).isoformat(),
    )
    state["settings"].setdefault("setup_complete", False)
    if not isinstance(state["settings"].get("interface"), str):
        raise SysmonError("traffic.json contains an invalid interface setting")
    try:
        limit = state["settings"].get("limit_bytes")
        limit = int(limit) if limit is not None else None
        quota_start = datetime.date.fromisoformat(state["settings"]["quota_start_date"])
    except (TypeError, ValueError):
        raise SysmonError("traffic.json contains invalid quota settings")
    if limit is not None and limit <= 0:
        raise SysmonError("traffic.json contains invalid quota settings")
    if quota_start > datetime.date.today():
        raise SysmonError("traffic.json contains a quota start date in the future")
    state["settings"]["limit_bytes"] = limit
    state["settings"]["setup_complete"] = bool(state["settings"]["setup_complete"])
    return state


def atomic_save(state):
    """Write JSON safely: temporary file in the same directory, fsync, then replace."""
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".traffic.", suffix=".tmp", dir=str(DATA_FILE.parent))
    try:
        # Traffic totals are not sensitive; allow normal users to view the UI.
        # Only root owns the directory and can modify the collector data.
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, str(DATA_FILE))
        try:
            directory_fd = os.open(str(DATA_FILE.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


class StateLock:
    def __enter__(self):
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.stream = LOCK_FILE.open("a+")
        fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        self.stream.close()


def get_counters():
    counters = psutil.net_io_counters(pernic=True, nowrap=False) or {}
    return counters


def collect_traffic():
    """Collect one outbound-counter delta. Called once at install and periodically."""
    with StateLock():
        counters = get_counters()
        state = load_state()
        now = int(time.time())
        current_boot = boot_marker()

        if state is None:
            state = empty_state()

        configured = state["settings"].get("interface", "auto")
        if configured and configured != "auto":
            interface = configured
            if interface not in counters:
                raise SysmonError("Configured interface '{}' is not present".format(interface))
        else:
            interface = detect_interface(counters)
            if not interface:
                raise SysmonError("Cannot determine the default outbound network interface")

        counter = int(counters[interface].bytes_sent)
        previous_counter = state.get("last_counter")
        previous_boot = state.get("boot_marker")
        previous_interface = state.get("interface")
        delta = 0
        message = "updated"

        if state.get("created_at") is None:
            state["created_at"] = now

        if previous_counter is None:
            message = "baseline initialized"
        elif previous_boot != current_boot:
            # Interface counters start over at boot. The current value represents
            # traffic already sent since this boot and can be recovered safely.
            delta = counter
            message = "system reboot detected; traffic since boot recovered"
            state.setdefault("notes", []).append({"time": now, "event": "reboot"})
        elif previous_interface != interface:
            message = "network interface changed; baseline reset"
            state.setdefault("notes", []).append({
                "time": now, "event": "interface_changed", "from": previous_interface, "to": interface
            })
        elif counter < int(previous_counter):
            message = "network counter reset; baseline reset"
            state.setdefault("notes", []).append({"time": now, "event": "counter_reset"})
        elif previous_boot == current_boot and previous_interface == interface and counter >= int(previous_counter):
            delta = counter - int(previous_counter)

        if delta > 0:
            day = datetime.date.fromtimestamp(now).isoformat()
            state["daily"][day] = int(state["daily"].get(day, 0)) + delta

        state["interface"] = interface
        state["last_counter"] = counter
        state["last_sample"] = now
        state["boot_marker"] = current_boot
        # Prevent unbounded growth of diagnostic events while retaining recent context.
        state["notes"] = state.get("notes", [])[-50:]
        atomic_save(state)
        return {"interface": interface, "delta": delta, "message": message}


def parse_size(value):
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB|KIB|MIB|GIB|TIB)?\s*", value, re.IGNORECASE)
    if not match:
        raise SysmonError("Invalid size. Examples: 500GB, 2TB, 1.5TiB")
    number = float(match.group(1))
    unit = (match.group(2) or "B").upper()
    powers_1000 = {"B": 1, "KB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3, "TB": 1000 ** 4}
    powers_1024 = {"KIB": 1024, "MIB": 1024 ** 2, "GIB": 1024 ** 3, "TIB": 1024 ** 4}
    multiplier = powers_1000.get(unit, powers_1024.get(unit))
    return int(number * multiplier)


def update_settings(
    interface=None,
    limit_bytes=None,
    set_limit=False,
    clear_limit=False,
    quota_start_date=None,
    setup_complete=None,
):
    with StateLock():
        state = load_state()
        if state is None:
            state = empty_state()
        settings = state["settings"]
        if interface is not None:
            settings["interface"] = interface
        if set_limit:
            settings["limit_bytes"] = limit_bytes
        if clear_limit:
            settings["limit_bytes"] = None
        if quota_start_date is not None:
            settings["quota_start_date"] = quota_start_date.isoformat()
        if setup_complete is not None:
            settings["setup_complete"] = bool(setup_complete)
        atomic_save(state)


def sum_range(daily, start_date, end_date):
    total = 0
    for day_text, amount in daily.items():
        try:
            day = datetime.date.fromisoformat(day_text)
        except (TypeError, ValueError):
            continue
        if start_date <= day <= end_date:
            total += int(amount)
    return total


def period_bounds(period, today=None, custom_from=None, custom_to=None):
    today = today or datetime.date.today()
    if period == "today":
        return today, today
    if period == "7d":
        return today - datetime.timedelta(days=6), today
    if period == "30d":
        return today - datetime.timedelta(days=29), today
    if period == "all":
        return datetime.date.min, today
    if period == "custom" and custom_from and custom_to:
        return custom_from, custom_to
    raise SysmonError("Invalid traffic period")


def parse_display_date(value):
    """Parse the user-facing DD.MM.YYYY date format."""
    if not re.fullmatch(r"\d{2}\.\d{2}\.\d{4}", value):
        raise ValueError("Use DD.MM.YYYY format")
    return datetime.datetime.strptime(value, "%d.%m.%Y").date()


def format_bytes(value):
    value = float(max(0, value))
    if value < 1000:
        return "{} B".format(int(value))
    for unit in ("KB", "MB", "GB", "TB", "PB"):
        value /= 1000.0
        if value < 1000 or unit == "PB":
            return "{:.1f} {}".format(value, unit)
    return "0 B"


def quota_text(state, today=None):
    settings = state.get("settings", {})
    limit = settings.get("limit_bytes")
    if limit is None:
        return "Quota: Unlimited"
    today = today or datetime.date.today()
    start_text = settings.get("quota_start_date")
    try:
        start = datetime.date.fromisoformat(start_text) if start_text else today
    except ValueError:
        start = today
    used = sum_range(state.get("daily", {}), start, today) if start <= today else 0
    used_gb = used / float(1000 ** 3)
    limit_gb = int(limit) / float(1000 ** 3)
    percent = (used / float(limit)) * 100.0 if limit else 0.0
    return "Quota: {:.2f} / {:.2f} GB ({:.1f}%)".format(used_gb, limit_gb, percent)


def prompt_first_run_setup():
    """Ask once for quota start date and quota limit; collector is already active."""
    state = load_state()
    if state is None:
        collect_traffic()
        state = load_state()
    if state and state.get("settings", {}).get("setup_complete"):
        return
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise SysmonError("First-run setup requires an interactive terminal")

    today = datetime.date.today()
    installed_at = datetime.date.fromtimestamp(int(state.get("created_at", time.time())))
    print("")
    print("Sysmon first-run setup")
    print("----------------------")
    print("Traffic collection is active since installation.")
    print("Only traffic collected by Sysmon can be included in quota totals.")
    print("")

    while True:
        raw_date = input("Quota start date (DD.MM.YYYY) [{}]: ".format(today.strftime("%d.%m.%Y"))).strip()
        try:
            start_date = parse_display_date(raw_date) if raw_date else today
            if start_date > today:
                raise ValueError("Date cannot be in the future")
            break
        except ValueError as exc:
            print("Invalid date: {}.".format(exc))

    if start_date < installed_at:
        print("Note: traffic before {} cannot be restored.".format(installed_at.strftime("%d.%m.%Y")))

    while True:
        raw_quota = input("Traffic quota in GB [Unlimited]: ").strip()
        if not raw_quota or raw_quota.lower() in ("unlimited", "none", "off"):
            limit_bytes = None
            break
        try:
            quota_gb = float(raw_quota)
            if quota_gb <= 0:
                raise ValueError
            limit_bytes = int(quota_gb * (1000 ** 3))
            break
        except ValueError:
            print("Enter a positive number of GB, or press Enter for Unlimited.")

    update_settings(
        limit_bytes=limit_bytes,
        set_limit=True,
        quota_start_date=start_date,
        setup_complete=True,
    )
    print("Settings saved.")
    print("")


def edit_quota_start_date(stdscr):
    """Prompt for a new quota calculation start date from the curses UI."""
    state, error = read_state_for_ui()
    if error or state is None:
        return "Traffic data unavailable"
    current = state.get("settings", {}).get("quota_start_date") or datetime.date.today().isoformat()
    try:
        current_date = datetime.date.fromisoformat(current)
    except ValueError:
        current_date = datetime.date.today()

    height, _ = stdscr.getmaxyx()
    row = height - 1
    prompt = "Quota start date (DD.MM.YYYY) [{}]: ".format(current_date.strftime("%d.%m.%Y"))
    stdscr.move(row, 0)
    stdscr.clrtoeol()
    safe_addstr(stdscr, row, 0, prompt, max(1, len(prompt)))
    stdscr.timeout(-1)
    stdscr.refresh()
    curses.echo()
    try:
        raw = stdscr.getstr(row, len(prompt), 10).decode("utf-8", "replace").strip()
    finally:
        curses.noecho()
        stdscr.timeout(1000)
    if not raw:
        return "Quota start date unchanged"
    try:
        selected = parse_display_date(raw)
        if selected > datetime.date.today():
            raise ValueError("Date cannot be in the future")
        update_settings(quota_start_date=selected, setup_complete=True)
        return "Quota start date updated"
    except ValueError as exc:
        return "Invalid date: {}".format(exc)


def read_state_for_ui():
    try:
        return load_state(), None
    except SysmonError as exc:
        return None, str(exc)


def draw_box(win, title, y, height, width, x):
    win.addstr(y, x, "┌" + "─" * (width - 2) + "┐")
    win.addstr(y, x + 2, title)
    for offset in range(1, height - 1):
        win.addstr(y + offset, x, "│" + " " * (width - 2) + "│")
    win.addstr(y + height - 1, x, "└" + "─" * (width - 2) + "┘")


def safe_addstr(win, y, x, text, max_width):
    try:
        win.addstr(y, x, str(text)[:max_width])
    except curses.error:
        pass


def selected_period_text(period, custom_from=None, custom_to=None):
    if period == "custom":
        return "Custom {} - {}".format(custom_from.strftime("%d.%m.%Y"), custom_to.strftime("%d.%m.%Y"))
    return PERIOD_LABELS[period]


def main(stdscr, args):
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(1000)

    periods = list(DEFAULT_PERIODS)
    current_period = args.period
    period_index = periods.index(current_period) if current_period in periods else -1
    custom_from = datetime.date.fromisoformat(args.from_date) if args.from_date else None
    custom_to = datetime.date.fromisoformat(args.to_date) if args.to_date else None

    while True:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        if width < BOX_WIDTH + 2 or height < 22:
            safe_addstr(stdscr, 0, 0, "Terminal too small: need at least 72x22", max(1, width - 1))
            stdscr.refresh()
            stdscr.getch()
            continue

        x = (width - BOX_WIDTH) // 2
        now = time.time()
        uptime = datetime.timedelta(seconds=int(now - psutil.boot_time()))
        cpu = psutil.cpu_percent(interval=0, percpu=False)
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage("/")
        io = psutil.disk_io_counters()

        # Keep the original Sysmon blocks, dimensions, coordinates and text style.
        draw_box(stdscr, " System ", 2, 3, BOX_WIDTH, x)
        safe_addstr(stdscr, 3, x + 3, "Uptime: {}".format(uptime), BOX_WIDTH - 6)

        bar_length = 50
        cpu_clamped = max(0, min(cpu, 100))
        filled = int(bar_length * cpu_clamped / 100)
        bar = ("█" * filled + "░" * (bar_length - filled))[:bar_length]
        draw_box(stdscr, " CPU ", 5, 3, BOX_WIDTH, x)
        safe_addstr(stdscr, 6, x + 3, "Usage: {:.1f}%   Cores: {}".format(cpu, bar), BOX_WIDTH - 6)

        used_gb = round(memory.used / (1024 ** 3), 1)
        total_gb = round(memory.total / (1024 ** 3), 1)
        swap_used = round(swap.used / (1024 ** 3), 1)
        swap_total = round(swap.total / (1024 ** 3), 1)
        draw_box(stdscr, " Memory ", 8, 3, BOX_WIDTH, x)
        safe_addstr(
            stdscr, 9, x + 3,
            "Used: {}G / {}G   Swap: {}G / {}G".format(used_gb, total_gb, swap_used, swap_total),
            BOX_WIDTH - 6,
        )

        draw_box(stdscr, " Disk ", 11, 3, BOX_WIDTH, x)
        read_speed = 0.0
        write_speed = 0.0
        # Disk I/O speed remains sampled by the UI, as in the original implementation.
        if not hasattr(main, "previous_io"):
            main.previous_io = io
            main.previous_io_time = now
        elapsed = max(0.001, now - main.previous_io_time)
        if io and main.previous_io:
            read_speed = max(0, io.read_bytes - main.previous_io.read_bytes) / (1024 ** 2) / elapsed
            write_speed = max(0, io.write_bytes - main.previous_io.write_bytes) / (1024 ** 2) / elapsed
        main.previous_io = io
        main.previous_io_time = now
        safe_addstr(
            stdscr, 12, x + 3,
            "Used: {}G / {}G   IO: {:.1f}MB/s read / {:.1f}MB/s write".format(
                round(disk.used / (1024 ** 3), 1), round(disk.total / (1024 ** 3), 1), read_speed, write_speed
            ),
            BOX_WIDTH - 6,
        )

        draw_box(stdscr, " Network ", 14, 4, BOX_WIDTH, x)
        state, state_error = read_state_for_ui()
        if state_error:
            first_line = "Traffic data unavailable"
            second_line = state_error
        elif state is None:
            first_line = "Traffic collector is not initialized"
            second_line = "Run the installer to initialize traffic collection"
        else:
            try:
                start_date, end_date = period_bounds(current_period, custom_from=custom_from, custom_to=custom_to)
                outgoing = sum_range(state.get("daily", {}), start_date, end_date)
                first_line = "Period: {}   Traffic: {}".format(
                    selected_period_text(current_period, custom_from, custom_to), format_bytes(outgoing)
                )
                second_line = quota_text(state)
                last_sample = state.get("last_sample")
                if last_sample and time.time() - int(last_sample) > 180:
                    second_line += "  [STALE]"
            except (SysmonError, ValueError, TypeError) as exc:
                first_line = "Traffic data unavailable"
                second_line = str(exc)
        safe_addstr(stdscr, 15, x + 3, first_line, BOX_WIDTH - 6)
        safe_addstr(stdscr, 16, x + 3, second_line, BOX_WIDTH - 6)

        draw_box(stdscr, " Hotkeys ", 18, 3, BOX_WIDTH, x)
        safe_addstr(stdscr, 19, x + 3, "P: period   D: quota start date   Q: quit", BOX_WIDTH - 6)

        stdscr.noutrefresh()
        curses.doupdate()

        key = stdscr.getch()
        if key in (ord("q"), ord("Q"), 27):
            break
        if key in (ord("p"), ord("P")):
            period_index = (period_index + 1) % len(periods)
            current_period = periods[period_index]
        elif key in (ord("d"), ord("D")):
            status = edit_quota_start_date(stdscr)
            safe_addstr(stdscr, height - 1, 0, status, width - 1)
            stdscr.refresh()
            time.sleep(1)


def build_parser():
    parser = argparse.ArgumentParser(description="Lightweight Unix system monitor")
    parser.add_argument("--version", action="version", version="Sysmon {}".format(VERSION))
    parser.add_argument("--collect", action="store_true", help="collect one outbound traffic sample and exit")
    parser.add_argument("--period", choices=DEFAULT_PERIODS, default="7d", help="initial traffic period in the UI")
    parser.add_argument("--from-date", help="custom period start date (YYYY-MM-DD)")
    parser.add_argument("--to-date", help="custom period end date (YYYY-MM-DD)")
    parser.add_argument("--set-limit", metavar="SIZE", help="set outbound traffic quota, e.g. 2000GB")
    parser.add_argument("--clear-limit", action="store_true", help="set the traffic quota to Unlimited")
    parser.add_argument("--quota-start-date", metavar="DD.MM.YYYY", help="set the quota calculation start date")
    parser.add_argument("--interface", help="set outbound interface name, or 'auto'")
    return parser


def main_cli():
    parser = build_parser()
    args = parser.parse_args()

    if args.from_date or args.to_date:
        if not (args.from_date and args.to_date):
            parser.error("--from-date and --to-date must be used together")
        try:
            start = datetime.date.fromisoformat(args.from_date)
            end = datetime.date.fromisoformat(args.to_date)
        except ValueError:
            parser.error("dates must use YYYY-MM-DD format")
        if start > end:
            parser.error("--from-date must not be later than --to-date")
        args.period = "custom"

    if args.set_limit and args.clear_limit:
        parser.error("--set-limit and --clear-limit cannot be used together")
    if args.set_limit and parse_size(args.set_limit) <= 0:
        parser.error("--set-limit must be greater than zero")

    if args.collect:
        result = collect_traffic()
        print("Sysmon traffic: {} | +{} | {}".format(
            result["interface"], format_bytes(result["delta"]), result["message"]
        ))
        return 0

    if any((args.set_limit is not None, args.clear_limit, args.quota_start_date is not None, args.interface is not None)):
        limit_bytes = parse_size(args.set_limit) if args.set_limit else None
        interface = args.interface
        if interface is not None and not interface:
            parser.error("--interface must be a name or 'auto'")
        quota_start_date = None
        if args.quota_start_date:
            try:
                quota_start_date = parse_display_date(args.quota_start_date)
                if quota_start_date > datetime.date.today():
                    raise ValueError("Date cannot be in the future")
            except ValueError as exc:
                parser.error("invalid --quota-start-date: {}".format(exc))
        update_settings(
            interface=interface,
            limit_bytes=limit_bytes,
            set_limit=args.set_limit is not None,
            clear_limit=args.clear_limit,
            quota_start_date=quota_start_date,
            setup_complete=(args.set_limit is not None or args.clear_limit or quota_start_date is not None),
        )
        print("Sysmon settings updated.")
        return 0

    if curses is None:
        raise SysmonError("Python was built without curses support; install a Python package with curses enabled")

    prompt_first_run_setup()

    try:
        curses.wrapper(main, args)
    except KeyboardInterrupt:
        return 0
    except curses.error as exc:
        print("Sysmon terminal error: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main_cli())
    except SysmonError as exc:
        print("Sysmon: {}".format(exc), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError) as exc:
        print("Sysmon: {}".format(exc), file=sys.stderr)
        sys.exit(1)
