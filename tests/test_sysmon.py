import datetime
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sysmon


class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.old_data_file = sysmon.DATA_FILE
        self.old_lock_file = sysmon.LOCK_FILE
        sysmon.DATA_FILE = root / "traffic.json"
        sysmon.LOCK_FILE = root / "traffic.lock"

    def tearDown(self):
        sysmon.DATA_FILE = self.old_data_file
        sysmon.LOCK_FILE = self.old_lock_file
        self.temp_dir.cleanup()

    def collect_with(self, counter, boot=1000):
        counters = {"eth0": SimpleNamespace(bytes_sent=counter)}
        with mock.patch.object(sysmon, "get_counters", return_value=counters), \
             mock.patch.object(sysmon, "detect_interface", return_value="eth0"), \
             mock.patch.object(sysmon, "boot_marker", return_value=boot):
            return sysmon.collect_traffic()

    def read_state(self):
        with sysmon.DATA_FILE.open("r", encoding="utf-8") as stream:
            return json.load(stream)

    def test_first_sample_creates_baseline_without_inventing_history(self):
        result = self.collect_with(1000)
        state = self.read_state()
        self.assertEqual(result["delta"], 0)
        self.assertEqual(result["message"], "baseline initialized")
        self.assertEqual(state["last_counter"], 1000)
        self.assertEqual(state["daily"], {})

    def test_counter_delta_is_added_to_current_day(self):
        self.collect_with(1000)
        result = self.collect_with(1500)
        state = self.read_state()
        today = datetime.date.fromtimestamp(state["last_sample"]).isoformat()
        self.assertEqual(result["delta"], 500)
        self.assertEqual(state["daily"][today], 500)

    def test_reboot_resets_baseline_without_negative_or_false_delta(self):
        self.collect_with(9000, boot=1000)
        result = self.collect_with(100, boot=2000)
        state = self.read_state()
        self.assertEqual(result["delta"], 0)
        self.assertIn("reboot", [note["event"] for note in state["notes"]])
        self.assertEqual(state["last_counter"], 100)

    def test_decreased_counter_resets_baseline(self):
        self.collect_with(9000)
        result = self.collect_with(100)
        state = self.read_state()
        self.assertEqual(result["delta"], 0)
        self.assertEqual(result["message"], "network counter reset; baseline reset")
        self.assertEqual(state["last_counter"], 100)

    def test_tunnel_default_route_falls_back_to_physical_interface(self):
        counters = {"wg0": SimpleNamespace(bytes_sent=5000), "eth0": SimpleNamespace(bytes_sent=9000)}
        with mock.patch.object(sysmon, "linux_default_interface", return_value="wg0"), \
             mock.patch.object(sysmon, "fallback_interface", return_value="eth0"), \
             mock.patch.object(sysmon.sys, "platform", "linux"):
            self.assertEqual(sysmon.detect_interface(counters), "eth0")

    def test_physical_default_route_is_preferred(self):
        counters = {"eth0": SimpleNamespace(bytes_sent=9000), "wg0": SimpleNamespace(bytes_sent=5000)}
        with mock.patch.object(sysmon, "linux_default_interface", return_value="eth0"), \
             mock.patch.object(sysmon.sys, "platform", "linux"):
            self.assertEqual(sysmon.detect_interface(counters), "eth0")

    def test_manual_interface_change_resets_baseline(self):
        self.collect_with(1000)
        state = self.read_state()
        state["settings"]["interface"] = "ens3"
        sysmon.atomic_save(state)
        counters = {"eth0": SimpleNamespace(bytes_sent=2000), "ens3": SimpleNamespace(bytes_sent=10)}
        with mock.patch.object(sysmon, "get_counters", return_value=counters), \
             mock.patch.object(sysmon, "boot_marker", return_value=1000):
            result = sysmon.collect_traffic()
        self.assertEqual(result["interface"], "ens3")
        self.assertEqual(result["delta"], 0)
        self.assertEqual(result["message"], "network interface changed; baseline reset")

    def test_atomic_json_round_trip_and_settings(self):
        self.collect_with(1000)
        sysmon.update_settings(limit_bytes=2_000_000_000_000, set_limit=True, reset_day=15)
        state = self.read_state()
        self.assertEqual(state["settings"]["limit_bytes"], 2_000_000_000_000)
        self.assertEqual(state["settings"]["reset_day"], 15)
        self.assertFalse(list(sysmon.DATA_FILE.parent.glob(".traffic.*.tmp")))


class FormattingAndPeriodTests(unittest.TestCase):
    def test_decimal_and_binary_size_units(self):
        self.assertEqual(sysmon.parse_size("2TB"), 2_000_000_000_000)
        self.assertEqual(sysmon.parse_size("1.5GiB"), int(1.5 * 1024 ** 3))
        self.assertEqual(sysmon.parse_size("500GB"), 500_000_000_000)

    def test_period_ranges_are_inclusive(self):
        today = datetime.date(2026, 11, 13)
        self.assertEqual(
            sysmon.period_bounds("7d", today=today),
            (datetime.date(2026, 11, 7), today),
        )
        self.assertEqual(
            sysmon.period_bounds("30d", today=today),
            (datetime.date(2026, 10, 15), today),
        )

    def test_custom_date_range_is_supported(self):
        start = datetime.date(2026, 11, 1)
        end = datetime.date(2026, 11, 13)
        self.assertEqual(
            sysmon.period_bounds("custom", custom_from=start, custom_to=end),
            (start, end),
        )

    def test_monthly_quota_reset_day(self):
        today = datetime.date(2026, 11, 13)
        self.assertEqual(sysmon.quota_period_start(today, 1), datetime.date(2026, 11, 1))
        self.assertEqual(sysmon.quota_period_start(today, 15), datetime.date(2026, 10, 15))

    def test_sum_range_uses_inclusive_dates(self):
        daily = {"2026-11-01": 100, "2026-11-02": 200, "2026-11-03": 300}
        total = sysmon.sum_range(daily, datetime.date(2026, 11, 2), datetime.date(2026, 11, 3))
        self.assertEqual(total, 500)


if __name__ == "__main__":
    unittest.main()
