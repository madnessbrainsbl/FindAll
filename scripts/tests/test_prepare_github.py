import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("prepare_github", Path(__file__).parents[1] / "prepare_github.py")
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


class PublicationTests(unittest.TestCase):
    def test_private_workspace_reference_is_removed_only_from_export(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve() / "source"
            document = root / "jobfind/AGENTS.md"
            document.parent.mkdir(parents=True)
            original = "`X:\\private\\other-project` is read-only. Do not copy its secrets."
            document.write_text(original, encoding="utf-8")
            destination = Path(folder) / "public"
            with patch.object(export, "source_files", return_value=iter([document])):
                export.prepare(root, destination)
            self.assertEqual(document.read_text(encoding="utf-8"), original)
            self.assertEqual((destination / "jobfind/AGENTS.md").read_text(encoding="utf-8"),
                             "Do not copy secrets from other projects.")

    def test_private_and_generated_files_are_excluded(self):
        for name in (
            "jobfind/profile.json", "jobfind/osint-keys.env", "jobfind/.env.local",
            "network/apex-state.json", "jobfind_out/report.json", "_archive/old.py",
            ".research/scrapling/baseline.html",
            "jobfind/jobfind.db-wal", "jobfind/third_party/tool/.git/config",
            "jobfind/third_party/tool/.github/workflows/release.yml",
            "jobfind/third_party/tool/uploads/observations.csv",
            "jobfind/third_party/tool/test/private-key-fixture.txt",
            "jobfind/.venv/config.py", "jobfind/rust-ui/target/debug/app.exe",
            "jobfind/third_party/tool/node_modules/index.js", "cookies.json",
        ):
            with self.subTest(name=name):
                self.assertFalse(export.publishable(Path(name)))
        for name in (".github/workflows/ci.yml", "jobfind/osint-keys.env.example",
                     "jobfind/profile.example.json", "jobfind/third_party/tool/LICENSE",
                     "docs/media/workspace.png", "docs/media/walkthrough.gif"):
            with self.subTest(name=name):
                self.assertTrue(export.publishable(Path(name)))

    def test_export_copies_source_and_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve() / "source"
            root.mkdir()
            document = root / "hello.py"
            document.write_text("print('hello')\n", encoding="utf-8")
            destination = Path(folder) / "public"
            with patch.object(export, "source_files", return_value=iter([document])):
                self.assertEqual(export.prepare(root, destination), 1)
            self.assertEqual(document.read_bytes(), (destination / "hello.py").read_bytes())
            self.assertEqual(list(destination.iterdir()), [destination / "hello.py"])
            with self.assertRaises(ValueError):
                export.prepare(root, destination)
            with self.assertRaises(ValueError):
                export.prepare(root, root.parent)


if __name__ == "__main__":
    unittest.main()
