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
import math
import os
import re
import shutil
import subprocess
import socket
import sys
import tempfile
import time
from pathlib import Path
from decimal import Decimal

import psutil

VERSION = "0.2.0-dev"
BOX_WIDTH = 70
DEFAULT_PERIODS = ("today", "7d", "30d", "month", "last_month", "all")
SAVED_PERIODS = DEFAULT_PERIODS + ("month_history",)
PERIOD_LABELS = {
    "today": "Today",
    "7d": "7 days",
    "30d": "30 days",
    "month": "Month",
    "last_month": "Last month",
    "all": "All time",
    "month_history": "Monthly history",
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
            "selected_period": "today",
            "selected_month": datetime.date.today().replace(day=1).isoformat(),
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
    # Remove the legacy manually configured quota date; quota periods are calendar months.
    state["settings"].pop("quota_start_date", None)
    state["settings"].setdefault("selected_period", "today")
    state["settings"].setdefault(
        "selected_month", datetime.date.today().replace(day=1).isoformat()
    )
    state["settings"].setdefault("setup_complete", False)
    if not isinstance(state["settings"].get("interface"), str):
        raise SysmonError("traffic.json contains an invalid interface setting")
    if state["settings"].get("selected_period") not in SAVED_PERIODS:
        raise SysmonError("traffic.json contains an invalid selected period")
    try:
        limit = state["settings"].get("limit_bytes")
        limit = int(limit) if limit is not None else None
        selected_month = datetime.date.fromisoformat(state["settings"]["selected_month"])
    except (TypeError, ValueError):
        raise SysmonError("traffic.json contains invalid settings")
    state["settings"]["selected_month"] = selected_month.replace(day=1).isoformat()
    if limit is not None and limit <= 0:
        raise SysmonError("traffic.json contains invalid quota settings")
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
        raise SysmonError("Invalid size. Examples: 500Gb, 2Tb, 1.5Tib")
    number = float(match.group(1))
    unit = (match.group(2) or "B").upper()
    powers_1000 = {"B": 1, "KB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3, "TB": 1000 ** 4}
    powers_1024 = {"KIB": 1024, "MIB": 1024 ** 2, "GIB": 1024 ** 3, "TIB": 1024 ** 4}
    multiplier = powers_1000.get(unit, powers_1024.get(unit))
    return int(number * multiplier)


def parse_quota_size(value):
    """Parse quota input in decimal Tb; bare numbers are treated as Tb."""
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*", value)
    if not match:
        raise ValueError("Enter a numeric quota in Tb only, for example: 0.5, 4.5, or 8")
    amount = Decimal(match.group(1))
    if not amount.is_finite() or amount <= 0:
        raise ValueError("Quota must be greater than zero")
    limit_bytes = int(amount * Decimal(1000 ** 4))
    if limit_bytes <= 0:
        raise ValueError("Quota must be at least one byte")
    return limit_bytes


def update_settings(
    interface=None,
    limit_bytes=None,
    set_limit=False,
    clear_limit=False,
    selected_period=None,
    selected_month=None,
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
        if selected_period is not None:
            if selected_period not in SAVED_PERIODS:
                raise SysmonError("Invalid selected period")
            settings["selected_period"] = selected_period
        if selected_month is not None:
            if not isinstance(selected_month, datetime.date):
                raise SysmonError("Invalid selected month")
            settings["selected_month"] = selected_month.replace(day=1).isoformat()
        if setup_complete is not None:
            settings["setup_complete"] = bool(setup_complete)
        atomic_save(state)


def reset_first_run_setup():
    """Reset only the first-run quota settings; preserve all collected counters and history."""
    with StateLock():
        state = load_state()
        if state is None:
            state = empty_state()
        settings = state["settings"]
        settings.pop("quota_start_date", None)
        settings["limit_bytes"] = None
        settings["selected_period"] = "today"
        settings["selected_month"] = datetime.date.today().replace(day=1).isoformat()
        settings["setup_complete"] = False
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
    if period == "month":
        return today.replace(day=1), today
    if period == "last_month":
        last_day_previous_month = today.replace(day=1) - datetime.timedelta(days=1)
        return last_day_previous_month.replace(day=1), last_day_previous_month
    if period == "all":
        return datetime.date.min, today
    if period == "custom" and custom_from and custom_to:
        return custom_from, custom_to
    raise SysmonError("Invalid traffic period")


def parse_display_date(value):
    """Parse user-facing DD-MM-YY dates; two-digit years map to 2000-2099."""
    if not re.fullmatch(r"\d{2}-\d{2}-\d{2}", value):
        raise ValueError("Use DD-MM-YY format")
    day, month, year = (int(part) for part in value.split("-"))
    return datetime.date(2000 + year, month, day)


def format_bytes(value):
    value = float(max(0, value))
    if value < 1000:
        return "{} B".format(int(value))
    for unit in ("KB", "Mb", "Gb", "Tb", "PB"):
        value /= 1000.0
        if value < 1000 or unit == "PB":
            return "{:.1f} {}".format(value, unit)
    return "0 B"


def _scaled_gigabyte_values(values, binary=False):
    """Scale bytes to Gb/Tb using decimal traffic units or binary system units."""
    base = float(1024 ** 3 if binary else 1000 ** 3)
    gigabytes = [
        None if value is None else max(0, int(value)) / base
        for value in values
    ]
    threshold = 1024.0 if binary else 1000.0
    if max((value or 0.0) for value in gigabytes) >= threshold:
        return [
            None if value is None else value / threshold
            for value in gigabytes
        ], "Tb", 2
    return gigabytes, "Gb", 1


def _format_scaled_amount(value, precision):
    """Round display values half-up, matching Sysmon's previous one-digit behavior."""
    factor = 10 ** precision
    rounded = math.floor(value * factor + 0.5) / float(factor)
    return "{:.{}f}".format(rounded, precision)


def format_gigabytes(value, binary=False):
    """Format one byte count as Gb or Tb, with a space before the unit."""
    values, unit, precision = _scaled_gigabyte_values([value], binary=binary)
    return "{} {}".format(_format_scaled_amount(values[0], precision), unit)


def format_gigabyte_pair(first_bytes, second_bytes, binary=False, integer_total=False):
    """Format two byte counts with one shared unit and a vertical separator."""
    values, unit, precision = _scaled_gigabyte_values(
        [first_bytes, second_bytes], binary=binary
    )
    total_precision = 0 if integer_total else precision
    first = "-" if values[0] is None else _format_scaled_amount(values[0], precision)
    second = "-" if values[1] is None else _format_scaled_amount(values[1], total_precision)
    return "{} | {} {}".format(first, second, unit)


def format_quota_pair(used_bytes, limit_bytes):
    """Format quota usage in the same adaptive units as Traffic and the limit in decimal Tb."""
    terabyte = float(1000 ** 4)
    used = "-" if used_bytes is None else format_gigabytes(max(0, used_bytes))
    limit_full = _format_scaled_amount(max(0, limit_bytes) / terabyte, 2)
    limit = limit_full.rstrip("0").rstrip(".")
    # Keep a visible zero precision for tiny legacy quotas instead of showing "0 Tb".
    if limit == "0":
        limit = limit_full
    return "{} | {} Tb".format(used, limit)


def data_start_date(state):
    """Return the first calendar day with data collection, based on installation."""
    return datetime.date.fromtimestamp(int(state.get("created_at", time.time())))


def tracking_start_date(state):
    """Return the configured quota start, never earlier than data collection."""
    settings = state.get("settings", {})
    installed_at = data_start_date(state)
    configured = settings.get("quota_start_date")
    try:
        selected = datetime.date.fromisoformat(configured) if configured else installed_at
    except (TypeError, ValueError):
        selected = installed_at
    return max(installed_at, selected)


def traffic_for_period(state, period, today=None, custom_from=None, custom_to=None):
    """Return TX bytes in the selected period, clipped to actual collection start."""
    today = today or datetime.date.today()
    start, end = period_bounds(period, today=today, custom_from=custom_from, custom_to=custom_to)
    end = min(end, today)
    collection_start = data_start_date(state)
    if end < collection_start:
        return None
    start = max(start, collection_start)
    if start > end:
        return None
    return sum_range(state.get("daily", {}), start, end)


def quota_text(state, today=None):
    """Return quota usage, or None when the quota is Unlimited."""
    settings = state.get("settings", {})
    limit = settings.get("limit_bytes")
    if limit is None:
        return None
    today = today or datetime.date.today()
    start = tracking_start_date(state)
    if today < start:
        values = format_quota_pair(None, limit)
    else:
        used = sum_range(state.get("daily", {}), start, today)
        values = format_quota_pair(used, limit)
    return "Quota: {}".format(values)


def network_status_line(state, period, today=None, custom_from=None, custom_to=None):
    today = today or datetime.date.today()
    traffic = traffic_for_period(
        state, period, today=today, custom_from=custom_from, custom_to=custom_to
    )
    traffic_value = "-" if traffic is None else format_gigabytes(traffic)
    period_label = selected_period_text(period, custom_from, custom_to)
    if period in ("month", "last_month"):
        period_start, period_end = period_bounds(period, today=today)
        if data_start_date(state) > period_start:
            period_label += "*"
    if period == "custom":
        period_label = "Custom"
    fields = [
        "Period: {}".format(period_label),
        "Traffic: {}".format(traffic_value),
    ]
    quota = quota_text(state, today=today)
    if quota is not None:
        fields.append(quota)
    line = "  ".join(fields)
    if len(line) > BOX_WIDTH - 6:
        compact_labels = {
            "today": "Today",
            "7d": "7 days",
            "30d": "30 days",
            "month": "Month",
            "last_month": "Last month",
            "all": "All time",
            "custom": "Custom",
        }
        compact_period = compact_labels.get(period, period_label)
        if period_label.endswith("*"):
            compact_period += "*"
        fields[0] = "Period: {}".format(compact_period)
        line = "  ".join(fields)
    return line


def preview_network_status_line(period, value_bytes):
    """Build a synthetic Network row for layout testing without reading or writing state."""
    period_labels = {
        "today": "Today",
        "7d": "7 days",
        "30d": "30 days",
        "month": "Month",
        "last_month": "Last month",
        "all": "All time",
        "custom": "Custom",
    }
    amount = format_gigabytes(value_bytes)
    quota = format_quota_pair(value_bytes, value_bytes)
    fields = [
        "Period: {}".format(period_labels.get(period, period)),
        "Traffic: {}".format(amount),
        "Quota: {}".format(quota),
    ]
    line = "  ".join(fields)
    if len(line) > BOX_WIDTH - 6:
        raise SysmonError(
            "Preview values exceed the current Network row width ({}/{})".format(
                len(line), BOX_WIDTH - 6
            )
        )
    return line


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
    if not os.access(DATA_FILE.parent, os.W_OK):
        raise SysmonError("First-run setup needs write access to traffic data. Run: sudo sysmon")

    today = datetime.date.today()
    installed_at = datetime.date.fromtimestamp(int(state.get("created_at", time.time())))
    print("")
    print("Sysmon first-run setup")
    print("----------------------")
    print("Traffic collection is active since installation.")
    print("The date below controls Quota only; Traffic periods include all collected data since installation.")
    print("")

    raw_date = input(
        "Quota start date (DD-MM-YY, day-month-year) [{}]: ".format(
            today.strftime("%d-%m-%y")
        )
    ).strip()
    start_date = today
    if raw_date:
        try:
            entered_date = parse_display_date(raw_date)
            if entered_date < installed_at:
                raise ValueError(
                    "Date cannot be earlier than installation ({})".format(
                        installed_at.strftime("%d-%m-%y")
                    )
                )
            start_date = entered_date
        except ValueError as exc:
            print(
                "Invalid date: {}. Using today's date ({}).".format(
                    exc, today.strftime("%d-%m-%y")
                ),
                flush=True,
            )
            time.sleep(5)

    if start_date > today:
        print("Quota usage will remain unavailable until the selected date.")

    raw_quota = input(
        "Traffic quota in Tb [blank = Unlimited]: "
    ).strip()
    limit_bytes = None
    if raw_quota and raw_quota.lower() not in ("unlimited", "none", "off"):
        try:
            limit_bytes = parse_quota_size(raw_quota)
        except ValueError:
            print(
                "Invalid quota. Using Unlimited.",
                flush=True,
            )
            time.sleep(5)

    update_settings(
        limit_bytes=limit_bytes,
        set_limit=True,
        quota_start_date=start_date,
        setup_complete=True,
    )
    print("Settings saved.")
    print("")


def read_hotkey_input(stdscr, prompt, max_chars):
    """Read a short value on the Hotkeys row without changing the layout."""
    _, width = stdscr.getmaxyx()
    row = 18
    start_x = (width - BOX_WIDTH) // 2 + 3
    content_width = BOX_WIDTH - 6
    safe_addstr(stdscr, row, start_x, " " * content_width, content_width)
    safe_addstr(stdscr, row, start_x, prompt, content_width)
    field_x = start_x + len(prompt)
    stdscr.timeout(-1)
    stdscr.refresh()
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    curses.echo()
    try:
        value = stdscr.getstr(row, field_x, max_chars).decode("utf-8", "replace").strip()
    finally:
        curses.noecho()
        stdscr.timeout(1000)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
    return value


def edit_quota_start_date(stdscr):
    """Change the date from which quota usage is accumulated."""
    state, error = read_state_for_ui()
    if error or state is None:
        return "Traffic data unavailable"
    today = datetime.date.today()
    installed_at = datetime.date.fromtimestamp(int(state.get("created_at", time.time())))
    prompt = "Quota start date DD-MM-YY [{}]: ".format(today.strftime("%d-%m-%y"))
    raw = read_hotkey_input(stdscr, prompt, 8)
    selected = today
    error_message = None
    if raw:
        try:
            entered_date = parse_display_date(raw)
            if entered_date < installed_at:
                raise ValueError(
                    "Date cannot be earlier than installation ({})".format(
                        installed_at.strftime("%d-%m-%y")
                    )
                )
            selected = entered_date
        except ValueError:
            error_message = "Invalid date; using today's date"
    try:
        update_settings(quota_start_date=selected, setup_complete=True)
        if error_message:
            return error_message
        if selected > today:
            return "Quota start date updated; quota starts {}".format(selected.strftime("%d-%m-%y"))
        return "Quota start date set to {}".format(selected.strftime("%d-%m-%y"))
    except (OSError, SysmonError) as exc:
        return "Cannot save start date: {}".format(exc)


def edit_traffic_quota(stdscr):
    """Change the outbound quota in decimal Tb; blank or invalid input means Unlimited."""
    state, error = read_state_for_ui()
    if error or state is None:
        return "Traffic data unavailable"
    prompt = "Traffic quota in Tb [blank = Unlimited]: "
    raw = read_hotkey_input(stdscr, prompt, 16)
    limit_bytes = None
    error_message = None
    if raw and raw.lower() not in ("unlimited", "none", "off"):
        try:
            limit_bytes = parse_quota_size(raw)
        except ValueError:
            error_message = "Invalid quota. Set to Unlimited."
    try:
        update_settings(limit_bytes=limit_bytes, set_limit=True, setup_complete=True)
        if error_message:
            return error_message
        return "Quota set to Unlimited" if limit_bytes is None else "Quota updated"
    except (OSError, SysmonError) as exc:
        return "Cannot save quota: {}".format(exc)


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
        return "Custom {} - {}".format(custom_from.strftime("%d-%m-%y"), custom_to.strftime("%d-%m-%y"))
    return PERIOD_LABELS[period]


def cpu_status_line(cpu, bar):
    """Keep the CPU value adjacent to Usage and hold Cores at a fixed column."""
    percentage = "{:.1f}%".format(cpu)
    padding = " " * max(0, 6 - len(percentage))
    return "Usage: {}{}   Cores: {}".format(percentage, padding, bar)


def standard_memory_capacity_bytes(total_bytes):
    """Round installed RAM to the nearest conventional power-of-two GiB tier."""
    if total_bytes <= 0:
        return total_bytes
    gib = total_bytes / float(1024 ** 3)
    exponent = max(0, int(math.floor(math.log(gib, 2) + 0.5)))
    return int((2 ** exponent) * (1024 ** 3))


def memory_status_line(memory_used, memory_total, swap_used, swap_total):
    """Render RAM capacity at a standard tier and keep actual usage unchanged."""
    memory_total = standard_memory_capacity_bytes(memory_total)
    return "Used: {}   Swap: {}".format(
        format_gigabyte_pair(memory_used, memory_total, binary=True, integer_total=True),
        format_gigabyte_pair(swap_used, swap_total, binary=True, integer_total=True),
    )


def disk_status_line(disk_used, disk_total, read_speed, write_speed):
    """Render disk capacity and I/O speeds using consistent separators."""
    return "Used: {}   IO: {:.1f} Mb/s read | {:.1f} Mb/s write".format(
        format_gigabyte_pair(disk_used, disk_total, binary=True, integer_total=True),
        read_speed,
        write_speed,
    )


def main(stdscr, args):
    curses.curs_set(0)
    stdscr.keypad(True)
    stdscr.timeout(1000)

    periods = list(DEFAULT_PERIODS)
    current_period = args.period or "today"
    period_index = periods.index(current_period) if current_period in periods else -1
    custom_from = parse_display_date(args.from_date) if args.from_date else None
    custom_to = parse_display_date(args.to_date) if args.to_date else None
    hotkey_status = None
    hotkey_status_until = 0.0

    while True:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        if width < BOX_WIDTH + 2 or height < 20:
            safe_addstr(stdscr, 0, 0, "Terminal too small: need at least 72x20", max(1, width - 1))
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
        safe_addstr(stdscr, 6, x + 3, cpu_status_line(cpu, bar), BOX_WIDTH - 6)

        draw_box(stdscr, " Memory ", 8, 3, BOX_WIDTH, x)
        safe_addstr(
            stdscr, 9, x + 3,
            memory_status_line(memory.used, memory.total, swap.used, swap.total),
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
            disk_status_line(disk.used, disk.total, read_speed, write_speed),
            BOX_WIDTH - 6,
        )

        draw_box(stdscr, " Network ", 14, 3, BOX_WIDTH, x)
        if args.preview_network is not None:
            try:
                network_line = preview_network_status_line(current_period, args.preview_network)
            except SysmonError as exc:
                network_line = "Preview unavailable: {}".format(exc)
        else:
            state, state_error = read_state_for_ui()
            if state_error:
                network_line = "Traffic data unavailable"
            elif state is None:
                network_line = "Traffic collector is not initialized"
            else:
                try:
                    network_line = network_status_line(
                        state, current_period, custom_from=custom_from, custom_to=custom_to
                    )
                    last_sample = state.get("last_sample")
                    if last_sample and time.time() - int(last_sample) > 180:
                        network_line += " [OLD]"
                except (SysmonError, ValueError, TypeError) as exc:
                    network_line = "Traffic data unavailable: {}".format(exc)
        safe_addstr(stdscr, 15, x + 3, network_line, BOX_WIDTH - 6)

        draw_box(stdscr, " Hotkeys ", 17, 3, BOX_WIDTH, x)
        if hotkey_status and time.monotonic() < hotkey_status_until:
            hotkeys_line = hotkey_status
        elif args.preview_network is not None:
            hotkey_status = None
            hotkeys_line = "P: period   Q: quit   PREVIEW MODE"
        else:
            hotkey_status = None
            hotkeys_line = "P: period   D: quota start date   L: quota   Q: quit"
        safe_addstr(stdscr, 18, x + 3, hotkeys_line, BOX_WIDTH - 6)

        stdscr.noutrefresh()
        curses.doupdate()

        key = stdscr.getch()
        if key in (ord("q"), ord("Q"), 27):
            break
        if key in (ord("p"), ord("P")):
            period_index = (period_index + 1) % len(periods)
            current_period = periods[period_index]
            if args.preview_network is None:
                try:
                    update_settings(selected_period=current_period)
                    hotkey_status = "Period saved: {}".format(PERIOD_LABELS[current_period])
                except (OSError, SysmonError) as exc:
                    hotkey_status = "Cannot save period: {}".format(exc)
                hotkey_status_until = time.monotonic() + 5.0
        elif key in (ord("d"), ord("D")) and args.preview_network is None:
            hotkey_status = edit_quota_start_date(stdscr)
            hotkey_status_until = time.monotonic() + 5.0
        elif key in (ord("l"), ord("L")) and args.preview_network is None:
            hotkey_status = edit_traffic_quota(stdscr)
            hotkey_status_until = time.monotonic() + 5.0


def build_parser():
    parser = argparse.ArgumentParser(description="Lightweight Unix system monitor")
    parser.add_argument("--version", action="version", version="Sysmon {}".format(VERSION))
    parser.add_argument("--collect", action="store_true", help="collect one outbound traffic sample and exit")
    parser.add_argument(
        "--preview-network",
        metavar="SIZE",
        help="preview the Network row with synthetic Traffic and Quota values; does not change stored data",
    )
    parser.add_argument("--period", choices=DEFAULT_PERIODS, help="initial traffic period in the UI (saved for next launch)")
    parser.add_argument("--from-date", metavar="DD-MM-YY", help="custom period start date")
    parser.add_argument("--to-date", metavar="DD-MM-YY", help="custom period end date")
    parser.add_argument(
        "--set-limit",
        metavar="TB",
        help="set outbound traffic quota in decimal Tb (numeric value only), e.g. 0.5, 4.5, or 8",
    )
    parser.add_argument("--clear-limit", action="store_true", help="set the traffic quota to Unlimited")
    parser.add_argument("--quota-start-date", metavar="DD-MM-YY", help="set the quota calculation start date")
    parser.add_argument(
        "--reset-setup",
        action="store_true",
        help="reset first-run date/quota settings without deleting traffic history",
    )
    parser.add_argument("--interface", help="set outbound interface name, or 'auto'")
    return parser


def main_cli():
    parser = build_parser()
    args = parser.parse_args()

    if args.from_date or args.to_date:
        if not (args.from_date and args.to_date):
            parser.error("--from-date and --to-date must be used together")
        try:
            start = parse_display_date(args.from_date)
            end = parse_display_date(args.to_date)
        except ValueError as exc:
            parser.error("dates must use DD-MM-YY format: {}".format(exc))
        if start > end:
            parser.error("--from-date must not be later than --to-date")
        args.period = "custom"

    if args.set_limit and args.clear_limit:
        parser.error("--set-limit and --clear-limit cannot be used together")
    if args.set_limit:
        try:
            parse_quota_size(args.set_limit)
        except ValueError as exc:
            parser.error("invalid --set-limit: {}".format(exc))

    preview_network_bytes = None
    if args.preview_network is not None:
        try:
            preview_network_bytes = parse_size(args.preview_network)
            if preview_network_bytes <= 0:
                raise ValueError("size must be greater than zero")
        except (SysmonError, ValueError) as exc:
            parser.error("invalid --preview-network: {}".format(exc))
        if any((
            args.collect,
            args.reset_setup,
            args.set_limit is not None,
            args.clear_limit,
            args.quota_start_date is not None,
            args.interface is not None,
        )):
            parser.error("--preview-network cannot be combined with collector or settings options")

    if args.reset_setup:
        if any((
            args.collect,
            args.set_limit is not None,
            args.clear_limit,
            args.quota_start_date is not None,
            args.interface is not None,
            args.from_date is not None,
            args.to_date is not None,
            args.period is not None,
        )):
            parser.error("--reset-setup cannot be combined with other options")
        reset_first_run_setup()
        print("First-run setup reset. Run 'sysmon' to enter the setup again.")
        return 0

    if args.collect:
        result = collect_traffic()
        print("Sysmon traffic: {} | +{} | {}".format(
            result["interface"], format_bytes(result["delta"]), result["message"]
        ))
        return 0

    if any((args.set_limit is not None, args.clear_limit, args.quota_start_date is not None, args.interface is not None)):
        limit_bytes = parse_quota_size(args.set_limit) if args.set_limit else None
        interface = args.interface
        if interface is not None and not interface:
            parser.error("--interface must be a name or 'auto'")
        quota_start_date = None
        if args.quota_start_date:
            try:
                quota_start_date = parse_display_date(args.quota_start_date)
                state = load_state()
                installed_at = (
                    datetime.date.fromtimestamp(int(state.get("created_at", time.time())))
                    if state else datetime.date.today()
                )
                if quota_start_date < installed_at:
                    raise ValueError(
                        "Date cannot be earlier than installation ({})".format(
                            installed_at.strftime("%d-%m-%y")
                        )
                    )
            except ValueError as exc:
                parser.error("invalid --quota-start-date: {}".format(exc))
        update_settings(
            interface=interface,
            limit_bytes=limit_bytes,
            set_limit=args.set_limit is not None,
            clear_limit=args.clear_limit,
            quota_start_date=quota_start_date,
            selected_period=args.period if args.period in DEFAULT_PERIODS else None,
            setup_complete=(args.set_limit is not None or args.clear_limit or quota_start_date is not None),
        )
        print("Sysmon settings updated.")
        return 0

    if curses is None:
        raise SysmonError("Python was built without curses support; install a Python package with curses enabled")

    if args.preview_network is None:
        try:
            prompt_first_run_setup()
        except KeyboardInterrupt:
            print("\\nSetup cancelled. Run sysmon again to complete first-run setup.")
            return 0
        if args.period is None:
            state = load_state()
            args.period = (
                state.get("settings", {}).get("selected_period", "today")
                if state else "today"
            )
        elif args.period in DEFAULT_PERIODS:
            update_settings(selected_period=args.period)
    else:
        args.preview_network = preview_network_bytes
        args.period = args.period or "today"

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
