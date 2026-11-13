import datetime
import io
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

    def test_reboot_recovers_traffic_sent_since_boot(self):
        self.collect_with(9000, boot=1000)
        result = self.collect_with(100, boot=2000)
        state = self.read_state()
        today = datetime.date.fromtimestamp(state["last_sample"]).isoformat()
        self.assertEqual(result["delta"], 100)
        self.assertEqual(state["daily"][today], 100)
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
        start_date = datetime.date.fromtimestamp(self.read_state()["created_at"])
        sysmon.update_settings(
            limit_bytes=2_000_000_000,
            set_limit=True,
            quota_start_date=start_date,
            setup_complete=True,
        )
        state = self.read_state()
        self.assertEqual(state["settings"]["limit_bytes"], 2_000_000_000)
        self.assertEqual(state["settings"]["quota_start_date"], start_date.isoformat())
        self.assertTrue(state["settings"]["setup_complete"])
        self.assertFalse(list(sysmon.DATA_FILE.parent.glob(".traffic.*.tmp")))

    def test_reset_first_run_setup_preserves_collected_traffic(self):
        self.collect_with(1000)
        today = datetime.date.today()
        install_date = datetime.date.fromtimestamp(self.read_state()["created_at"])
        configured_date = max(install_date, today - datetime.timedelta(days=1))
        sysmon.update_settings(
            quota_start_date=configured_date,
            limit_bytes=2_000_000_000,
            set_limit=True,
            setup_complete=True,
        )
        # Keep representative collected totals and the collector baseline.
        state = self.read_state()
        state["daily"][today.isoformat()] = 987_654_321
        state["last_counter"] = 123_456_789
        state["interface"] = "eth0"
        sysmon.atomic_save(state)

        sysmon.reset_first_run_setup()
        reset = self.read_state()

        self.assertFalse(reset["settings"]["setup_complete"])
        self.assertEqual(reset["settings"]["quota_start_date"], today.isoformat())
        self.assertIsNone(reset["settings"]["limit_bytes"])
        self.assertEqual(reset["daily"], state["daily"])
        self.assertEqual(reset["last_counter"], state["last_counter"])
        self.assertEqual(reset["interface"], state["interface"])
        self.assertEqual(reset["created_at"], state["created_at"])

    def test_unlimited_is_default_quota(self):
        self.collect_with(1000)
        state = self.read_state()
        self.assertIsNone(state["settings"]["limit_bytes"])
        self.assertEqual(sysmon.quota_text(state), "Quota: Unlimited")

    def test_quota_uses_selected_start_date(self):
        self.collect_with(1000)
        state = self.read_state()
        state["settings"]["limit_bytes"] = 2_000_000_000
        today = datetime.date.today()
        start = today - datetime.timedelta(days=3)
        state["created_at"] = int(datetime.datetime.combine(
            today - datetime.timedelta(days=10), datetime.time.min
        ).timestamp())
        state["settings"]["quota_start_date"] = start.isoformat()
        state["daily"] = {
            (start - datetime.timedelta(days=1)).isoformat(): 9_000_000_000,
            start.isoformat(): 250_000_000,
            (today - datetime.timedelta(days=1)).isoformat(): 500_000_000,
            today.isoformat(): 250_000_000,
        }
        self.assertEqual(
            sysmon.quota_text(state, today=today),
            "Quota: 1.0G / 2.0G",
        )

    def test_first_run_setup_defaults_to_today_and_unlimited(self):
        self.collect_with(1000)
        class FakeTTY(io.StringIO):
            def isatty(self):
                return True
        with mock.patch.object(sysmon.sys, "stdin", FakeTTY()), \
             mock.patch.object(sysmon.sys, "stdout", FakeTTY()), \
             mock.patch("builtins.input", side_effect=["", ""]):
            sysmon.prompt_first_run_setup()
        state = self.read_state()
        self.assertEqual(state["settings"]["quota_start_date"], datetime.date.today().isoformat())
        self.assertIsNone(state["settings"]["limit_bytes"])
        self.assertTrue(state["settings"]["setup_complete"])

    def test_first_run_setup_accepts_custom_date_and_quota_gb(self):
        self.collect_with(1000)
        class FakeTTY:
            def isatty(self):
                return True
        future_start = datetime.date.today() + datetime.timedelta(days=5)
        with mock.patch.object(sysmon.sys, "stdin", FakeTTY()), \
             mock.patch.object(sysmon.sys, "stdout", FakeTTY()), \
             mock.patch("builtins.input", side_effect=[future_start.strftime("%d.%m.%Y"), "2"]):
            sysmon.prompt_first_run_setup()
        state = self.read_state()
        self.assertEqual(state["settings"]["quota_start_date"], future_start.isoformat())
        self.assertEqual(state["settings"]["limit_bytes"], 2_000_000_000)
        self.assertTrue(state["settings"]["setup_complete"])

    def test_start_date_cannot_be_earlier_than_installation(self):
        self.collect_with(1000)
        installed_at = datetime.date.fromtimestamp(self.read_state()["created_at"])
        with self.assertRaises(sysmon.SysmonError):
            sysmon.update_settings(quota_start_date=installed_at - datetime.timedelta(days=1))

    def test_future_start_date_is_allowed_and_displays_dashes(self):
        self.collect_with(1000)
        future = datetime.date.today() + datetime.timedelta(days=5)
        sysmon.update_settings(
            quota_start_date=future,
            limit_bytes=2_000_000_000,
            set_limit=True,
            setup_complete=True,
        )
        state = self.read_state()
        self.assertIsNone(sysmon.traffic_for_period(state, "today"))
        self.assertEqual(sysmon.quota_text(state), "Quota: - / 2.0G")
        self.assertIn("Traffic: -", sysmon.network_status_line(state, "today"))

    def test_unlimited_quota_remains_visible_with_future_start_date(self):
        self.collect_with(1000)
        future = datetime.date.today() + datetime.timedelta(days=2)
        sysmon.update_settings(quota_start_date=future, limit_bytes=None, set_limit=True)
        state = self.read_state()
        line = sysmon.network_status_line(state, "today")
        self.assertIn("Traffic: -", line)
        self.assertIn("Quota: Unlimited", line)


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

    def test_display_date_requires_dd_mm_yyyy_format(self):
        self.assertEqual(sysmon.parse_display_date("13.11.2026"), datetime.date(2026, 11, 13))
        with self.assertRaises(ValueError):
            sysmon.parse_display_date("2026-11-13")

    def test_sum_range_uses_inclusive_dates(self):
        daily = {"2026-11-01": 100, "2026-11-02": 200, "2026-11-03": 300}
        total = sysmon.sum_range(daily, datetime.date(2026, 11, 2), datetime.date(2026, 11, 3))
        self.assertEqual(total, 500)

    def test_traffic_is_formatted_in_decimal_gb_to_one_digit(self):
        self.assertEqual(sysmon.format_gigabytes(3_000_000), "<0.1G")
        self.assertEqual(sysmon.format_gigabytes(100_000_000), "0.1G")
        self.assertEqual(sysmon.format_gigabytes(1_250_000_000), "1.3G")

    def test_selected_period_is_clipped_to_tracking_start_date(self):
        today = datetime.date.today()
        install = today - datetime.timedelta(days=10)
        start = today - datetime.timedelta(days=3)
        daily = {
            (start - datetime.timedelta(days=1)).isoformat(): 9_000_000_000,
            start.isoformat(): 100_000_000,
            today.isoformat(): 200_000_000,
        }
        state = {
            "created_at": int(datetime.datetime.combine(install, datetime.time.min).timestamp()),
            "settings": {"quota_start_date": start.isoformat(), "limit_bytes": None},
            "daily": daily,
        }
        self.assertEqual(sysmon.traffic_for_period(state, "all", today=today), 300_000_000)

    def test_network_line_fits_existing_box_width(self):
        today = datetime.date.today()
        state = {
            "created_at": int(datetime.datetime.combine(
                today - datetime.timedelta(days=10), datetime.time.min
            ).timestamp()),
            "settings": {
                "quota_start_date": (today - datetime.timedelta(days=5)).isoformat(),
                "limit_bytes": 2_000_000_000_000,
            },
            "daily": {today.isoformat(): 125_000_000_000},
        }
        line = sysmon.network_status_line(state, "30d", today=today)
        self.assertLessEqual(len(line), sysmon.BOX_WIDTH - 6)
        self.assertIn("Quota: 125.0G / 2000.0G", line)


if __name__ == "__main__":
    unittest.main()
