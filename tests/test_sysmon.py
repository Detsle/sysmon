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
        self.assertIsNone(sysmon.quota_text(state))
        self.assertNotIn("Quota:", sysmon.network_status_line(state, "today"))

    def test_quota_uses_selected_start_date(self):
        self.collect_with(1000)
        state = self.read_state()
        state["settings"]["limit_bytes"] = 2_000_000_000_000
        today = datetime.date.today()
        start = today - datetime.timedelta(days=3)
        state["created_at"] = int(datetime.datetime.combine(
            today - datetime.timedelta(days=10), datetime.time.min
        ).timestamp())
        state["settings"]["quota_start_date"] = start.isoformat()
        state["daily"] = {
            (start - datetime.timedelta(days=1)).isoformat(): 9_000_000_000_000,
            start.isoformat(): 250_000_000_000,
            (today - datetime.timedelta(days=1)).isoformat(): 500_000_000_000,
            today.isoformat(): 250_000_000_000,
        }
        self.assertEqual(
            sysmon.quota_text(state, today=today),
            "Quota: 1.00 | 2 Tb",
        )

    def test_first_run_setup_defaults_to_today_and_unlimited(self):
        self.collect_with(1000)
        class FakeTTY(io.StringIO):
            def isatty(self):
                return True
        with mock.patch.object(sysmon.sys, "stdin", FakeTTY()), \
             mock.patch.object(sysmon.sys, "stdout", FakeTTY()), \
             mock.patch("builtins.input", side_effect=["", ""]) as input_mock:
            sysmon.prompt_first_run_setup()
        state = self.read_state()
        self.assertEqual(state["settings"]["quota_start_date"], datetime.date.today().isoformat())
        self.assertIsNone(state["settings"]["limit_bytes"])
        self.assertTrue(state["settings"]["setup_complete"])
        date_prompt = input_mock.call_args_list[0].args[0]
        self.assertEqual(
            date_prompt,
            "Traffic start date (DD-MM-YY, day-month-year) [{}]: ".format(
                datetime.date.today().strftime("%d-%m-%y")
            ),
        )
        quota_prompt = input_mock.call_args_list[1].args[0]
        self.assertEqual(quota_prompt, "Traffic quota in Tb [blank = Unlimited]: ")

    def test_first_run_setup_accepts_custom_date_and_quota_tb(self):
        self.collect_with(1000)
        class FakeTTY(io.StringIO):
            def isatty(self):
                return True
        future_start = datetime.date.today() + datetime.timedelta(days=5)
        with mock.patch.object(sysmon.sys, "stdin", FakeTTY()), \
             mock.patch.object(sysmon.sys, "stdout", FakeTTY()), \
             mock.patch("builtins.input", side_effect=[future_start.strftime("%d-%m-%y"), "2"]):
            sysmon.prompt_first_run_setup()
        state = self.read_state()
        self.assertEqual(state["settings"]["quota_start_date"], future_start.isoformat())
        self.assertEqual(state["settings"]["limit_bytes"], 2_000_000_000_000)
        self.assertTrue(state["settings"]["setup_complete"])

    def test_first_run_quota_bare_number_is_interpreted_as_tb(self):
        self.collect_with(1000)

        class FakeTTY(io.StringIO):
            def isatty(self):
                return True

        with mock.patch.object(sysmon.sys, "stdin", FakeTTY()), \
             mock.patch.object(sysmon.sys, "stdout", FakeTTY()), \
             mock.patch("builtins.input", side_effect=["", "8"]):
            sysmon.prompt_first_run_setup()

        state = self.read_state()
        self.assertEqual(state["settings"]["limit_bytes"], 8_000_000_000_000)
        self.assertEqual(sysmon.quota_text(state), "Quota: 0.0 Gb | 8 Tb")

    def test_first_run_invalid_date_and_quota_use_defaults(self):
        self.collect_with(1000)
        installed_at = datetime.date.fromtimestamp(self.read_state()["created_at"])
        invalid_date = (installed_at - datetime.timedelta(days=1)).strftime("%d-%m-%y")

        class FakeTTY(io.StringIO):
            def isatty(self):
                return True

        fake_stdout = FakeTTY()
        with mock.patch.object(sysmon.sys, "stdin", FakeTTY()), \
             mock.patch.object(sysmon.sys, "stdout", fake_stdout), \
             mock.patch("builtins.input", side_effect=[invalid_date, "not-a-number"]), \
             mock.patch.object(sysmon.time, "sleep") as sleep:
            sysmon.prompt_first_run_setup()

        state = self.read_state()
        self.assertEqual(state["settings"]["quota_start_date"], datetime.date.today().isoformat())
        self.assertIsNone(state["settings"]["limit_bytes"])
        self.assertTrue(state["settings"]["setup_complete"])
        self.assertEqual(sleep.call_count, 2)
        self.assertIn("Using today's date", fake_stdout.getvalue())
        self.assertIn("Using Unlimited", fake_stdout.getvalue())

    def test_blank_hotkey_date_resets_to_today(self):
        self.collect_with(1000)
        today = datetime.date.today()
        with mock.patch.object(sysmon, "read_hotkey_input", return_value=""):
            status = sysmon.edit_quota_start_date(None)
        state = self.read_state()
        self.assertEqual(state["settings"]["quota_start_date"], today.isoformat())
        self.assertEqual(
            status,
            "Start date set to {}".format(today.strftime("%d-%m-%y")),
        )

    def test_invalid_hotkey_date_uses_today(self):
        self.collect_with(1000)
        today = datetime.date.today()
        with mock.patch.object(sysmon, "read_hotkey_input", return_value="31-02-26") as read_input:
            status = sysmon.edit_quota_start_date(None)
        self.assertTrue(read_input.call_args.args[1].startswith("Traffic start date DD-MM-YY ["))
        self.assertEqual(read_input.call_args.args[2], 8)
        state = self.read_state()
        self.assertEqual(state["settings"]["quota_start_date"], today.isoformat())
        self.assertIn("Invalid date", status)

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
            limit_bytes=2_000_000_000_000,
            set_limit=True,
            setup_complete=True,
        )
        state = self.read_state()
        self.assertIsNone(sysmon.traffic_for_period(state, "today"))
        self.assertEqual(sysmon.quota_text(state), "Quota: - | 2 Tb")
        self.assertIn("Traffic: -", sysmon.network_status_line(state, "today"))

    def test_unlimited_quota_is_hidden_with_future_start_date(self):
        self.collect_with(1000)
        future = datetime.date.today() + datetime.timedelta(days=2)
        sysmon.update_settings(quota_start_date=future, limit_bytes=None, set_limit=True)
        state = self.read_state()
        line = sysmon.network_status_line(state, "today")
        self.assertIn("Traffic: -", line)
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
                "quota_start_date": (today - datetime.timedelta(days=5)).isoformat(),
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
                "quota_start_date": install.isoformat(),
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

    def test_memory_and_disk_totals_are_rounded_to_integers(self):
        gib = 1024 ** 3
        memory_line = sysmon.memory_status_line(
            gib,
            round(7.8 * gib),
            0,
            8 * gib,
        )
        self.assertEqual(
            memory_line,
            "Used: 1.0 | 8 Gb   Swap: 0.0 | 8 Gb",
        )

        disk_line = sysmon.disk_status_line(
            round(29.4 * gib),
            round(147.6 * gib),
            0.0,
            0.0,
        )
        self.assertEqual(
            disk_line,
            "Used: 29.4 | 148 Gb   IO: 0.0 Mb/s read | 0.0 Mb/s write",
        )
        self.assertLessEqual(len(disk_line), sysmon.BOX_WIDTH - 6)

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

    def test_period_labels_use_requested_lowercase_style(self):
        self.assertEqual(sysmon.selected_period_text("7d"), "7 days")
        self.assertEqual(sysmon.selected_period_text("30d"), "30 days")
        self.assertEqual(sysmon.selected_period_text("all"), "All time")

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
