"""CLI global values must not be mistaken for a subcommand."""
import unittest
from unittest.mock import patch

import jobfind


class CliArgumentTests(unittest.TestCase):
    def test_draft_file_survives_global_arguments_before_command(self):
        for globals_ in (["--db", "state.db", "--out", "reports", "--network", "direct"],
                         ["--db=state.db", "--network=direct"]):
            with self.subTest(globals_=globals_), patch.object(jobfind, "cmd_draft", return_value=0) as command:
                self.assertEqual(jobfind.main([*globals_, "draft", "--id", "1", "--out", "letter.txt"]), 0)
                args = command.call_args.args[0]
                self.assertEqual(args.db, "state.db")
                self.assertEqual(args.out, "letter.txt")

    def test_draft_without_file_does_not_use_global_report_directory(self):
        with patch.object(jobfind, "cmd_draft", return_value=0) as command:
            self.assertEqual(jobfind.main(["--db", "state.db", "--out", "reports", "draft", "--id", "1"]), 0)
            self.assertEqual(command.call_args.args[0].out, "")

    def test_report_directory_still_works_after_command(self):
        with patch.object(jobfind, "cmd_report", return_value=0) as command:
            self.assertEqual(jobfind.main(["report", "--out", "reports", "--db", "state.db"]), 0)
            self.assertEqual(command.call_args.args[0].out, "reports")
            self.assertEqual(command.call_args.args[0].db, "state.db")
