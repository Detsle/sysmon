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

    def test_traffic_accumulates_when_quota_is_unlimited(self):
        self.collect_with(1000)
        self.collect_with(4200)
        state = self.read_state()
        today = datetime.date.fromtimestamp(state["last_sample"]).isoformat()
        self.assertIsNone(state["settings"]["limit_bytes"])
        self.assertEqual(state["daily"][today], 3200)

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
        sysmon.update_settings(
            limit_bytes=2_000_000_000,
            set_limit=True,
            setup_complete=True,
        )
        state = self.read_state()
        self.assertEqual(state["settings"]["limit_bytes"], 2_000_000_000)
        self.assertTrue(state["settings"]["setup_complete"])
        self.assertFalse(list(sysmon.DATA_FILE.parent.glob(".traffic.*.tmp")))

    def test_reset_first_run_setup_preserves_collected_traffic(self):
        self.collect_with(1000)
        today = datetime.date.today()
        sysmon.update_settings(
            limit_bytes=2_000_000_000,
            set_limit=True,
            setup_complete=True,
        )
        # Keep representative collected totals and the collector baseline.
        state = self.read_state()
        state["daily"][today.isoformat()] = 987_654_321
        state["last_counter"] = 123_456_789
        state["interface"] = "eth0"
        state["settings"]["selected_period"] = "month_history"
        state["settings"]["selected_month"] = today.replace(day=1).isoformat()
        sysmon.atomic_save(state)

        sysmon.reset_first_run_setup()
        reset = self.read_state()

        self.assertFalse(reset["settings"]["setup_complete"])
        self.assertNotIn('quota_start_date', reset['settings'])
        self.assertEqual(reset['settings']['selected_month'], today.replace(day=1).isoformat())
        self.assertIsNone(reset["settings"]["limit_bytes"])
        self.assertEqual(reset["daily"], state["daily"])
        self.assertEqual(reset["last_counter"], state["last_counter"])
        self.assertEqual(reset["interface"], state["interface"])
        self.assertEqual(reset["created_at"], state["created_at"])
        self.assertEqual(reset["settings"]["selected_period"], "month_history")
        self.assertEqual(reset["settings"]["selected_month"], today.replace(day=1).isoformat())

    def test_selected_period_persists_and_legacy_state_defaults_to_today(self):
        self.collect_with(1000)
        state = self.read_state()
        del state["settings"]["selected_period"]
        sysmon.atomic_save(state)

        loaded = sysmon.load_state()
        self.assertEqual(loaded["settings"]["selected_period"], "today")

        selected = datetime.date.today().replace(day=1)
        sysmon.update_settings(
            selected_period="month_history",
            selected_month=selected,
        )
        saved = self.read_state()["settings"]
        self.assertEqual(saved["selected_period"], "month_history")
        self.assertEqual(saved["selected_month"], selected.isoformat())

    def test_main_cli_restores_saved_month_history_selection(self):
        self.collect_with(1000)
        selected = datetime.date.today().replace(day=1)
        sysmon.update_settings(
            selected_period="month_history",
            selected_month=selected,
            setup_complete=True,
        )
        captured = {}

        def fake_wrapper(callback, args):
            captured["period"] = args.period
            captured["selected_month"] = args.selected_month

        with mock.patch.object(sysmon.sys, "argv", ["sysmon"]), \
             mock.patch.object(sysmon, "prompt_first_run_setup"), \
             mock.patch.object(sysmon.curses, "wrapper", side_effect=fake_wrapper):
            self.assertEqual(sysmon.main_cli(), 0)

        self.assertEqual(captured["period"], "month_history")
        self.assertEqual(captured["selected_month"], selected)

    def test_unlimited_is_default_quota(self):
        self.collect_with(1000)
        state = self.read_state()
        self.assertIsNone(state["settings"]["limit_bytes"])
        self.assertIsNone(sysmon.quota_text(state))
        self.assertNotIn("Quota:", sysmon.network_status_line(state, "today"))

    def test_quota_resets_by_calendar_month_and_uses_actual_month_length(self):
        install = datetime.date(2026, 1, 15)
        state = {
            "created_at": int(datetime.datetime.combine(install, datetime.time.min).timestamp()),
            "settings": {"limit_bytes": 8_000_000_000_000},
            "daily": {
                "2026-01-14": 99_000_000_000,
                "2026-01-15": 2_000_000_000,
                "2026-01-31": 3_000_000_000,
                "2026-02-01": 4_000_000_000,
                "2026-02-28": 5_000_000_000,
            },
        }
        self.assertEqual(
            sysmon.quota_text(
                state, today=datetime.date(2026, 2, 28), month_start=datetime.date(2026, 1, 1)
            ),
            "Quota: 5.0 Gb | 8 Tb",
        )
        self.assertEqual(
            sysmon.quota_text(
                state, today=datetime.date(2026, 2, 28), month_start=datetime.date(2026, 2, 1)
            ),
            "Quota: 9.0 Gb | 8 Tb",
        )

    def test_first_run_setup_defaults_to_unlimited_monthly_quota(self):
        self.collect_with(1000)
        class FakeTTY(io.StringIO):
            def isatty(self):
                return True
        fake_stdout = FakeTTY()
        with mock.patch.object(sysmon.sys, "stdin", FakeTTY()), \
             mock.patch.object(sysmon.sys, "stdout", fake_stdout), \
             mock.patch("builtins.input", side_effect=[""]) as input_mock:
            sysmon.prompt_first_run_setup()
        state = self.read_state()
        self.assertNotIn("quota_start_date", state["settings"])
        self.assertEqual(state["settings"]["selected_period"], "today")
        self.assertIsNone(state["settings"]["limit_bytes"])
        self.assertTrue(state["settings"]["setup_complete"])
        self.assertIn("Traffic collection is active since installation.", fake_stdout.getvalue())
        self.assertIn("Traffic and quota usage are grouped by calendar month.", fake_stdout.getvalue())
        self.assertIn("The first accounting month may be partial.", fake_stdout.getvalue())
        self.assertEqual(
            input_mock.call_args.args[0],
            "Traffic quota in Tb [blank = Unlimited]: ",
        )

    def test_first_run_setup_accepts_numeric_monthly_quota(self):
        self.collect_with(1000)
        class FakeTTY(io.StringIO):
            def isatty(self):
                return True
        with mock.patch.object(sysmon.sys, "stdin", FakeTTY()), \
             mock.patch.object(sysmon.sys, "stdout", FakeTTY()), \
             mock.patch("builtins.input", side_effect=["2"]):
            sysmon.prompt_first_run_setup()
        state = self.read_state()
        self.assertEqual(state["settings"]["limit_bytes"], 2_000_000_000_000)
        self.assertTrue(state["settings"]["setup_complete"])

    def test_first_run_quota_bare_number_is_interpreted_as_tb(self):
        self.collect_with(1000)

        class FakeTTY(io.StringIO):
            def isatty(self):
                return True

        with mock.patch.object(sysmon.sys, "stdin", FakeTTY()), \
             mock.patch.object(sysmon.sys, "stdout", FakeTTY()), \
             mock.patch("builtins.input", side_effect=["8"]):
            sysmon.prompt_first_run_setup()

        state = self.read_state()
        self.assertEqual(state["settings"]["limit_bytes"], 8_000_000_000_000)
        self.assertEqual(sysmon.quota_text(state), "Quota: 0.0 Gb | 8 Tb")

    def test_first_run_invalid_quota_falls_back_to_unlimited(self):
        self.collect_with(1000)
        class FakeTTY(io.StringIO):
            def isatty(self):
                return True
        fake_stdout = FakeTTY()
        with mock.patch.object(sysmon.sys, "stdin", FakeTTY()), \
             mock.patch.object(sysmon.sys, "stdout", fake_stdout), \
             mock.patch("builtins.input", side_effect=["not-a-number"]), \
             mock.patch.object(sysmon.time, "sleep") as sleep:
            sysmon.prompt_first_run_setup()
        state = self.read_state()
        self.assertNotIn("quota_start_date", state["settings"])
        self.assertIsNone(state["settings"]["limit_bytes"])
        self.assertTrue(state["settings"]["setup_complete"])
        self.assertEqual(sleep.call_count, 1)
        self.assertIn("Using Unlimited", fake_stdout.getvalue())


    def test_blank_hotkey_quota_sets_unlimited(self):
        self.collect_with(1000)
        with mock.patch.object(sysmon, "read_hotkey_input", return_value=""):
            status = sysmon.edit_traffic_quota(None)
        state = self.read_state()
        self.assertIsNone(state["settings"]["limit_bytes"])
        self.assertIn("Unlimited", status)

    def test_invalid_hotkey_quota_sets_unlimited(self):
        self.collect_with(1000)
        with mock.patch.object(sysmon, "read_hotkey_input", return_value="NaN"):
            status = sysmon.edit_traffic_quota(None)
        state = self.read_state()
        self.assertIsNone(state["settings"]["limit_bytes"])
        self.assertIn("Invalid quota", status)

    def test_hotkey_quota_rejects_unit_suffix(self):
        self.collect_with(1000)
        with mock.patch.object(sysmon, "read_hotkey_input", return_value="8Tb") as read_input:
            status = sysmon.edit_traffic_quota(None)
        state = self.read_state()
        self.assertIsNone(state["settings"]["limit_bytes"])
        self.assertIn("Invalid quota", status)
        self.assertEqual(read_input.call_args.args[1], "Traffic quota in Tb [blank = Unlimited]: ")

    def test_hotkey_quota_accepts_numeric_decimal_tb(self):
        self.collect_with(1000)
        with mock.patch.object(sysmon, "read_hotkey_input", return_value="4.5"):
            status = sysmon.edit_traffic_quota(None)
        state = self.read_state()
        self.assertEqual(state["settings"]["limit_bytes"], 4_500_000_000_000)
        self.assertEqual(sysmon.quota_text(state), "Quota: 0.0 Gb | 4.5 Tb")
        self.assertEqual(status, "Quota updated")

    def test_cli_set_limit_accepts_numeric_tb_only(self):
        self.collect_with(1000)
        for quota_input, expected_bytes in (
            ("8", 8_000_000_000_000),
            ("0.5", 500_000_000_000),
            ("4.5", 4_500_000_000_000),
        ):
            with self.subTest(quota_input=quota_input), \
                 mock.patch.object(sysmon.sys, "argv", ["sysmon", "--set-limit", quota_input]), \
                 mock.patch("builtins.print"):
                self.assertEqual(sysmon.main_cli(), 0)
            state = self.read_state()
            self.assertEqual(state["settings"]["limit_bytes"], expected_bytes)

        with mock.patch.object(sysmon.sys, "argv", ["sysmon", "--set-limit", "8Tb"]), \
             mock.patch("builtins.print"):
            with self.assertRaises(SystemExit) as error:
                sysmon.main_cli()
        self.assertEqual(error.exception.code, 2)


    def test_legacy_manual_quota_date_is_removed_without_losing_daily_history(self):
        self.collect_with(1000)
        state = self.read_state()
        state["settings"]["quota_start_date"] = "2026-01-15"
        state["daily"]["2026-01-15"] = 5_000_000_000
        sysmon.atomic_save(state)
        migrated = sysmon.load_state()
        self.assertNotIn("quota_start_date", migrated["settings"])
        self.assertEqual(migrated["daily"], state["daily"])
        self.assertEqual(
            migrated["settings"]["selected_month"],
            datetime.date.today().replace(day=1).isoformat(),
        )

    def test_legacy_state_ignores_pre_collector_history_and_clamps_month_selection(self):
        self.collect_with(1000)
        state = self.read_state()
        old_install = datetime.datetime(2026, 10, 1).timestamp()
        state["created_at"] = int(old_install)
        state.pop("accounting_started_at", None)
        state["daily"] = {
            "2026-10-15": 50_000_000_000,
            "2026-11-13": 3_000_000_000,
        }
        state["settings"]["selected_period"] = "last_month"
        state["settings"]["selected_month"] = "2026-10-01"
        state["settings"]["limit_bytes"] = 8_000_000_000_000
        sysmon.atomic_save(state)

        migrated = sysmon.load_state()
        trusted_start = datetime.date.fromtimestamp(sysmon.TRAFFIC_COLLECTOR_INTRODUCED_AT)
        self.assertEqual(sysmon.data_start_date(migrated), trusted_start)
        self.assertIsNone(migrated["last_counter"])
        self.assertIsNone(migrated["last_sample"])
        self.assertEqual(migrated["settings"]["selected_period"], "today")
        self.assertEqual(migrated["settings"]["selected_month"], trusted_start.replace(day=1).isoformat())
        self.assertEqual(
            sysmon.quota_text(
                migrated,
                today=datetime.date(2026, 11, 13),
                month_start=datetime.date(2026, 10, 1),
            ),
            "Quota: - | 8 Tb",
        )
        history_line = sysmon.network_status_line(
            migrated,
            "month_history",
            today=datetime.date(2026, 11, 13),
            selected_month=datetime.date(2026, 10, 1),
        )
        self.assertIn("Period: Nov ’26", history_line)
        self.assertIn("Traffic: 3.0 Gb", history_line)
        self.assertNotIn("Oct", history_line)

    def test_standard_periods_always_show_the_current_month_quota(self):
        state = {
            "created_at": int(datetime.datetime(2026, 11, 1).timestamp()),
            "accounting_started_at": int(datetime.datetime(2026, 11, 1).timestamp()),
            "settings": {"limit_bytes": 8_000_000_000_000},
            "daily": {
                "2026-10-31": 90_000_000_000,
                "2026-11-13": 3_000_000_000,
            },
        }
        line = sysmon.network_status_line(
            state, "all", today=datetime.date(2026, 11, 13)
        )
        self.assertIn("Quota: 3.0 Gb | 8 Tb", line)
        self.assertNotIn("90.0 Gb", line)

    def test_unlimited_quota_remains_hidden_in_network_line(self):
        self.collect_with(1000)
        state = self.read_state()
        line = sysmon.network_status_line(state, "today")
        self.assertIn("Traffic: 0.0 Gb", line)
        self.assertNotIn("Quota:", line)


    def test_preview_network_parser_accepts_size_without_modifying_data(self):
        self.collect_with(123456)
        before = sysmon.DATA_FILE.read_bytes()
        args = sysmon.build_parser().parse_args(["--preview-network", "100000GB"])
        self.assertEqual(sysmon.parse_size(args.preview_network), 100_000_000_000_000)
        self.assertEqual(sysmon.DATA_FILE.read_bytes(), before)

    def test_preview_network_mode_skips_first_run_setup_and_preserves_json(self):
        self.collect_with(123456)
        before = sysmon.DATA_FILE.read_bytes()
        captured = {}

        def fake_wrapper(callback, args):
            captured["preview_network"] = args.preview_network

        with mock.patch.object(sysmon.sys, "argv", ["sysmon", "--preview-network", "100000GB"]), \
             mock.patch.object(sysmon, "prompt_first_run_setup") as setup, \
             mock.patch.object(sysmon.curses, "wrapper", side_effect=fake_wrapper):
            result = sysmon.main_cli()

        self.assertEqual(result, 0)
        self.assertEqual(captured["preview_network"], 100_000_000_000_000)
        setup.assert_not_called()
        self.assertEqual(sysmon.DATA_FILE.read_bytes(), before)

    def test_network_line_fits_existing_box_width(self):
        today = datetime.date.today()
        state = {
            "created_at": int(datetime.datetime.combine(
                today - datetime.timedelta(days=10), datetime.time.min
            ).timestamp()),
            "settings": {
                "limit_bytes": 2_000_000_000_000,
            },
            "daily": {today.isoformat(): 125_000_000_000},
        }
        line = sysmon.network_status_line(state, "30d", today=today)
        self.assertLessEqual(len(line), sysmon.BOX_WIDTH - 6)
        self.assertIn("Quota: 125.0 Gb | 2 Tb", line)


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

    def test_calendar_period_labels_include_month_and_year(self):
        today = datetime.date(2026, 2, 15)
        self.assertEqual(sysmon.selected_period_text("month", today=today), "1 month")
        self.assertEqual(sysmon.selected_period_text("last_month", today=today), "Jan ’26")
        self.assertEqual(
            sysmon.selected_period_text(
                "month_history", today=today, selected_month=datetime.date(2025, 12, 1)
            ),
            "Dec ’25",
        )

    def test_network_box_title_has_no_partial_month_marker(self):
        self.assertEqual(sysmon.NETWORK_BOX_TITLE, " Network ")

    def test_calendar_month_periods_respect_month_lengths_and_leap_years(self):
        self.assertEqual(
            sysmon.period_bounds("month", today=datetime.date(2026, 2, 13)),
            (datetime.date(2026, 2, 1), datetime.date(2026, 2, 13)),
        )
        self.assertEqual(
            sysmon.period_bounds(
                "month_history", today=datetime.date(2026, 2, 13),
                selected_month=datetime.date(2025, 12, 1),
            ),
            (datetime.date(2025, 12, 1), datetime.date(2025, 12, 31)),
        )
        self.assertEqual(
            sysmon.shift_calendar_month(datetime.date(2025, 12, 1), 1),
            datetime.date(2026, 1, 1),
        )
        self.assertEqual(
            sysmon.shift_calendar_month(datetime.date(2026, 1, 1), -1),
            datetime.date(2025, 12, 1),
        )
        self.assertEqual(
            sysmon.period_bounds("last_month", today=datetime.date(2026, 3, 1)),
            (datetime.date(2026, 2, 1), datetime.date(2026, 2, 28)),
        )
        self.assertEqual(
            sysmon.period_bounds("last_month", today=datetime.date(2024, 3, 1)),
            (datetime.date(2024, 2, 1), datetime.date(2024, 2, 29)),
        )

    def test_month_history_shows_selected_month_traffic_and_quota_with_year(self):
        install = datetime.date(2026, 1, 1)
        state = {
            "created_at": int(datetime.datetime.combine(install, datetime.time.min).timestamp()),
            "settings": {"limit_bytes": 8_000_000_000_000},
            "daily": {
                "2026-01-31": 2_000_000_000,
                "2026-02-01": 3_000_000_000,
            },
        }
        line = sysmon.network_status_line(
            state,
            "month_history",
            today=datetime.date(2026, 2, 15),
            selected_month=datetime.date(2026, 1, 1),
        )
        self.assertIn("Period: Jan ’26", line)
        self.assertIn("Traffic: 2.0 Gb", line)
        self.assertIn("Quota: 2.0 Gb | 8 Tb", line)

    def test_monthly_traffic_includes_all_collected_days_since_installation(self):
        install = datetime.date(2026, 1, 1)
        today = datetime.date(2026, 1, 31)
        state = {
            "created_at": int(datetime.datetime.combine(install, datetime.time.min).timestamp()),
            "settings": {
                "limit_bytes": None,
            },
            "daily": {
                "2026-01-01": 9_000_000_000,
                "2026-01-14": 8_000_000_000,
                "2026-01-15": 2_000_000_000,
                "2026-01-31": 1_000_000_000,
            },
        }
        line = sysmon.network_status_line(state, "month", today=today)
        self.assertIn("Period: 1 month", line)
        self.assertNotIn("*", line)
        self.assertIn("Traffic: 20.0 Gb", line)

    def test_calendar_month_is_partial_only_when_collection_started_mid_month(self):
        install = datetime.date(2026, 1, 15)
        today = datetime.date(2026, 1, 31)
        state = {
            "created_at": int(datetime.datetime.combine(install, datetime.time.min).timestamp()),
            "settings": {
                "limit_bytes": None,
            },
            "daily": {
                "2026-01-01": 9_000_000_000,
                "2026-01-14": 8_000_000_000,
                "2026-01-15": 2_000_000_000,
                "2026-01-31": 1_000_000_000,
            },
        }
        line = sysmon.network_status_line(state, "month", today=today)
        self.assertIn("Period: 1 month", line)
        self.assertNotIn("*", line)
        self.assertIn("Traffic: 3.0 Gb", line)

    def test_custom_date_range_is_supported(self):
        start = datetime.date(2026, 11, 1)
        end = datetime.date(2026, 11, 13)
        self.assertEqual(
            sysmon.period_bounds("custom", custom_from=start, custom_to=end),
            (start, end),
        )
        self.assertEqual(
            sysmon.selected_period_text("custom", custom_from=start, custom_to=end),
            "Custom 01-11-26 - 13-11-26",
        )

    def test_cli_custom_period_accepts_dd_mm_yy(self):
        args = sysmon.build_parser().parse_args([
            "--from-date", "01-11-26", "--to-date", "13-11-26"
        ])
        start = sysmon.parse_display_date(args.from_date)
        end = sysmon.parse_display_date(args.to_date)
        self.assertEqual(start, datetime.date(2026, 11, 1))
        self.assertEqual(end, datetime.date(2026, 11, 13))

    def test_display_date_requires_dd_mm_yy_format(self):
        self.assertEqual(sysmon.parse_display_date("13-11-26"), datetime.date(2026, 11, 13))
        for invalid in ("13.11.26", "13-11-2026", "2026-11-13", "31-02-26"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                sysmon.parse_display_date(invalid)
        self.assertEqual(sysmon.parse_display_date("01-01-69"), datetime.date(2069, 1, 1))
        self.assertEqual(sysmon.parse_display_date("01-01-99"), datetime.date(2099, 1, 1))
        self.assertEqual(sysmon.parse_display_date("01-01-00"), datetime.date(2000, 1, 1))

    def test_100_tb_values_fit_today_and_30_days_network_rows(self):
        today = datetime.date.today()
        install = today - datetime.timedelta(days=10)
        amount = 100_000 * 1_000_000_000
        state = {
            "created_at": int(datetime.datetime.combine(install, datetime.time.min).timestamp()),
            "settings": {
                "limit_bytes": amount,
            },
            "daily": {today.isoformat(): amount},
        }
        for period, label in (("today", "Today"), ("30d", "30 days")):
            with self.subTest(period=period):
                line = sysmon.network_status_line(state, period, today=today)
                self.assertLessEqual(len(line), sysmon.BOX_WIDTH - 6)
                self.assertIn("Period: {}".format(label), line)
                self.assertIn("Traffic: 100.00 Tb", line)
                self.assertIn("Quota: 100.00 | 100 Tb", line)

    def test_memory_and_disk_capacity_totals_show_one_decimal_without_overstatement(self):
        gib = 1024 ** 3
        memory_line = sysmon.memory_status_line(
            round(5.36 * gib),
            round(15.30 * gib),
            0,
            4 * gib,
        )
        self.assertEqual(
            memory_line,
            "Used: 5.4 | 15.3 Gb   Swap: 0.0 | 4.0 Gb",
        )

        disk_line = sysmon.disk_status_line(
            round(105.53 * gib),
            round(431.49 * gib),
            0.0,
            0.0,
        )
        self.assertEqual(
            disk_line,
            "Used: 105.5 | 431.4 Gb   IO: 0.0 Mb/s read | 0.0 Mb/s write",
        )
        self.assertLessEqual(len(disk_line), sysmon.BOX_WIDTH - 6)

    def test_nonstandard_memory_capacity_is_not_snapped_to_nominal_tier(self):
        gib = 1024 ** 3
        self.assertEqual(
            sysmon.memory_status_line(round(1.0 * gib), round(7.75 * gib), 0, round(3.9 * gib)),
            "Used: 1.0 | 7.7 Gb   Swap: 0.0 | 3.9 Gb",
        )

    def test_sum_range_uses_inclusive_dates(self):
        daily = {"2026-11-01": 100, "2026-11-02": 200, "2026-11-03": 300}
        total = sysmon.sum_range(daily, datetime.date(2026, 11, 2), datetime.date(2026, 11, 3))
        self.assertEqual(total, 500)

    def test_traffic_is_formatted_in_decimal_gb_to_one_digit(self):
        self.assertEqual(sysmon.format_gigabytes(3_000_000), "0.0 Gb")
        self.assertEqual(sysmon.format_gigabytes(100_000_000), "0.1 Gb")
        self.assertEqual(sysmon.format_gigabytes(1_250_000_000), "1.3 Gb")

    def test_gigabytes_convert_to_terabytes_at_decimal_1000_gb(self):
        self.assertEqual(sysmon.format_gigabytes(999_900_000_000), "999.9 Gb")
        self.assertEqual(sysmon.format_gigabytes(1_000_000_000_000), "1.00 Tb")
        self.assertEqual(sysmon.format_gigabytes(1_110_000_000_000), "1.11 Tb")
        self.assertEqual(sysmon.format_gigabytes(8_000_000_000_000), "8.00 Tb")
        self.assertEqual(
            sysmon.format_gigabyte_pair(1_000_000_000_000, 5_500_000_000),
            "1.00 | 0.01 Tb",
        )
        self.assertEqual(
            sysmon.format_gigabyte_pair(1024 * (1024 ** 3), 5 * (1024 ** 3), binary=True),
            "1.00 | 0.00 Tb",
        )

    def test_quota_input_accepts_numeric_decimal_tb_only(self):
        self.assertEqual(sysmon.parse_quota_size("0.5"), 500_000_000_000)
        self.assertEqual(sysmon.parse_quota_size("4.5"), 4_500_000_000_000)
        self.assertEqual(sysmon.parse_quota_size("8"), 8_000_000_000_000)
        with self.assertRaises(ValueError):
            sysmon.parse_quota_size("8Tb")
        with self.assertRaises(ValueError):
            sysmon.parse_quota_size("0.5 Tb")
        with self.assertRaises(ValueError):
            sysmon.parse_quota_size("8000Gb")
        with self.assertRaises(ValueError):
            sysmon.parse_quota_size("0")
        with self.assertRaises(ValueError):
            sysmon.parse_quota_size("0.0000000000001")
        with self.assertRaises(ValueError):
            sysmon.parse_quota_size("invalid")

    def test_five_gib_file_size_formats_as_decimal_gigabytes(self):
        five_gib = 5 * (1024 ** 3)
        self.assertEqual(sysmon.format_gigabytes(five_gib), "5.4 Gb")

    def test_quota_usage_below_five_gb_is_visible_in_gb(self):
        self.assertEqual(
            sysmon.format_quota_pair(3_200_000_000, 8_000_000_000_000),
            "3.2 Gb | 8 Tb",
        )

    def test_quota_limit_is_shown_without_trailing_decimal_zeros(self):
        self.assertEqual(
            sysmon.format_quota_pair(0, 8_000_000_000_000),
            "0.0 Gb | 8 Tb",
        )
        self.assertEqual(
            sysmon.format_quota_pair(0, 4_500_000_000_000),
            "0.0 Gb | 4.5 Tb",
        )
        self.assertEqual(
            sysmon.format_quota_pair(0, 500_000_000_000),
            "0.0 Gb | 0.5 Tb",
        )

    def test_tiny_existing_quota_does_not_display_as_zero_tb(self):
        self.assertEqual(
            sysmon.format_quota_pair(0, 2_000_000_000),
            "0.0 Gb | 0.00 Tb",
        )

    def test_format_bytes_uses_requested_mb_gb_tb_casing(self):
        self.assertEqual(sysmon.format_bytes(1_000_000), "1.0 Mb")
        self.assertEqual(sysmon.format_bytes(1_000_000_000), "1.0 Gb")
        self.assertEqual(sysmon.format_bytes(1_000_000_000_000), "1.0 Tb")

    def test_cpu_value_starts_after_one_space_and_cores_column_is_fixed(self):
        low = sysmon.cpu_status_line(0.0, "█" * 50)
        high = sysmon.cpu_status_line(100.0, "█" * 50)
        self.assertTrue(low.startswith("Usage: 0.0%"))
        self.assertTrue(high.startswith("Usage: 100.0%"))
        self.assertEqual(low.index("Cores:"), high.index("Cores:"))

    def test_standard_period_labels_remain_available(self):
        self.assertEqual(sysmon.selected_period_text("7d"), "7 days")
        self.assertEqual(sysmon.selected_period_text("month"), "1 month")
        self.assertEqual(sysmon.DEFAULT_PERIODS, ("today", "7d", "month", "all"))
        self.assertEqual(sysmon.selected_period_text("30d"), "30 days")
        self.assertEqual(sysmon.selected_period_text("all"), "All time")

    def test_selected_period_is_clipped_to_actual_collection_start(self):
        today = datetime.date.today()
        install = today - datetime.timedelta(days=10)
        quota_start = today - datetime.timedelta(days=3)
        daily = {
            (quota_start - datetime.timedelta(days=1)).isoformat(): 9_000_000_000,
            quota_start.isoformat(): 100_000_000,
            today.isoformat(): 200_000_000,
        }
        state = {
            "created_at": int(datetime.datetime.combine(install, datetime.time.min).timestamp()),
            "settings": {"limit_bytes": None},
            "daily": daily,
        }
        self.assertEqual(sysmon.traffic_for_period(state, "all", today=today), 9_300_000_000)

    def test_preview_network_line_fits_100_tb_in_existing_box(self):
        value = sysmon.parse_size("100000GB")
        line = sysmon.preview_network_status_line("30d", value)
        self.assertEqual(
            line,
            "Period: 30 days  Traffic: 100.00 Tb  Quota: 100.00 | 100 Tb",
        )
        self.assertLessEqual(len(line), sysmon.BOX_WIDTH - 6)

    def test_preview_100_tb_today_period_does_not_raise_layout_error(self):
        value = sysmon.parse_size("100000GB")
        line = sysmon.preview_network_status_line("today", value)
        self.assertEqual(
            line,
            "Period: Today  Traffic: 100.00 Tb  Quota: 100.00 | 100 Tb",
        )
        self.assertLessEqual(len(line), sysmon.BOX_WIDTH - 6)



if __name__ == "__main__":
    unittest.main()
