import curses
import psutil
import time
import datetime

def draw_box(win, title, y, h, w, x):
    win.addstr(y, x, "┌" + "─"*(w-2) + "┐")
    win.addstr(y, x+2, title)
    for i in range(1, h-1):
        win.addstr(y+i, x, "│" + " "*(w-2) + "│")
    win.addstr(y+h-1, x, "└" + "─"*(w-2) + "┘")

def main(stdscr):
    curses.curs_set(0)
    h, w = stdscr.getmaxyx()
    box_width = 70
    x = (w - box_width) // 2

    prev_io = psutil.disk_io_counters()
    prev_time = time.time()

    while True:

        # System
        uptime = datetime.timedelta(seconds=int(time.time() - psutil.boot_time()))
        draw_box(stdscr, " System ", 2, 3, box_width, x)
        stdscr.addstr(3, x+3, f"Uptime: {uptime}")

        # CPU
        cpu = psutil.cpu_percent(interval=0, percpu=False)
        bar_length = 50
        cpu_clamped = max(0, min(cpu, 100))
        filled = int(bar_length * cpu_clamped / 100)
        empty = bar_length - filled
        bar = ('█' * filled + '░' * empty)[:bar_length]
        line = f"Usage: {cpu:.1f}%   Cores: {bar}"
        line = line[:box_width-6]
        draw_box(stdscr, " CPU ", 5, 3, box_width, x)
        stdscr.addstr(6, x+3, line)

        # Memory
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        used_gb = round(mem.used / (1024**3), 1)
        total_gb = round(mem.total / (1024**3), 1)
        swap_used = round(swap.used / (1024**3), 1)
        swap_total = round(swap.total / (1024**3), 1)
        draw_box(stdscr, " Memory ", 8, 3, box_width, x)
        stdscr.addstr(9, x+3, f"Used: {used_gb}G / {total_gb}G   Swap: {swap_used}G / {swap_total}G")

        # Disk
        disk = psutil.disk_usage('/')
        io = psutil.disk_io_counters()
        now = time.time()
        elapsed = now - prev_time if now > prev_time else 1.0

        read_speed = (io.read_bytes - prev_io.read_bytes) / (1024**2) / elapsed
        write_speed = (io.write_bytes - prev_io.write_bytes) / (1024**2) / elapsed

        draw_box(stdscr, " Disk ", 11, 3, box_width, x)
        stdscr.addstr(
            12, x+3,
            f"Used: {round(disk.used/(1024**3),1)}G / {round(disk.total/(1024**3),1)}G   IO: {read_speed:.1f}MB/s read / {write_speed:.1f}MB/s write"
        )

        prev_io = io
        prev_time = now

        stdscr.noutrefresh()
        curses.doupdate()
        time.sleep(1)

curses.wrapper(main)
