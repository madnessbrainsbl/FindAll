"""Windows launcher checks with a disposable native process, never the user's app."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


@unittest.skipUnless(os.name == "nt", "Windows batch/PowerShell launcher")
class LauncherChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="findall-launch-probe-")
        cls.probe = Path(cls.temporary.name) / "probe.exe"
        cls.powershell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
        source = """$ErrorActionPreference = 'Stop'
Add-Type -OutputAssembly $env:FINDALL_PROBE_EXE -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
public class LauncherProbe {
    public static int Main(string[] args) {
        string[] lines = new string[args.Length + 1];
        lines[0] = Process.GetCurrentProcess().MainModule.FileName;
        Array.Copy(args, 0, lines, 1, args.Length);
        File.WriteAllLines(Environment.GetEnvironmentVariable("FINDALL_PROBE_RESULT"), lines);
        return 0;
    }
}
'@
"""
        run = subprocess.run([cls.powershell, "-NoProfile", "-NonInteractive", "-Command", source],
            env={**os.environ, "FINDALL_PROBE_EXE": str(cls.probe)}, capture_output=True, timeout=40)
        if run.returncode:
            cls.temporary.cleanup()
            raise AssertionError(run.stderr.decode(errors="replace"))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def prepare(self, root):
        project = Path(__file__).resolve().parents[1]
        app = root / "jobfind"
        app.mkdir()
        shutil.copy2(project.parent / "start.bat", root / "start.bat")
        for name in ("start.bat", "start.ps1", "archives.bat", "wireless.bat"):
            shutil.copy2(project / name, app / name)
        return app

    def binary(self, path, stamp):
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.probe, path)
        os.utime(path, (stamp, stamp))

    def launch(self, entry, output, arguments):
        command = "& $env:FINDALL_PROBE_ENTRY " + arguments
        run = subprocess.run([self.powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            env={**os.environ, "FINDALL_PROBE_ENTRY": str(entry), "FINDALL_PROBE_RESULT": str(output)},
            capture_output=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
        return output.read_text(encoding="utf-8-sig").splitlines()

    def test_newest_current_binary_wins_and_arguments_survive_spaces_and_cyrillic(self):
        for root_time, release_time, legacy_time, expected in (
                (100, 200, None, "rust-ui/target/release/findall-ui.exe"),
                (200, 100, None, "findall-ui.exe"),
                (None, 200, None, "rust-ui/target/release/findall-ui.exe"),
                (200, None, None, "findall-ui.exe"),
                (None, None, 300, "jobfind-ui.exe"),
                (100, None, 300, "findall-ui.exe")):
            with self.subTest(expected=expected, root=root_time), tempfile.TemporaryDirectory(prefix="FindAll путь & '") as temp:
                root = Path(temp)
                app = self.prepare(root)
                for relative, stamp in (("findall-ui.exe", root_time), ("rust-ui/target/release/findall-ui.exe", release_time), ("jobfind-ui.exe", legacy_time)):
                    if stamp is not None:
                        self.binary(app / relative, stamp)
                lines = self.launch(root / "start.bat", root / "result.txt", "--page browser --label 'Два слова & more'")
                self.assertEqual(Path(lines[0]).resolve(), (app / expected).resolve())
                self.assertEqual(lines[1:], ["--page", "browser", "--label", "Два слова & more"])

    def test_section_launchers_share_binary_selection_and_forward_arguments(self):
        with tempfile.TemporaryDirectory(prefix="FindAll section ") as temp:
            root = Path(temp)
            app = self.prepare(root)
            newest = app / "rust-ui/target/release/findall-ui.exe"
            self.binary(app / "findall-ui.exe", 100)
            self.binary(newest, 200)
            for section in ("archives", "wireless"):
                lines = self.launch(app / (section + ".bat"), root / (section + ".txt"), "--label 'two words'")
                self.assertEqual(Path(lines[0]).resolve(), newest.resolve())
                self.assertEqual(lines[1:], ["--page", section, "--label", "two words"])

    def test_wireless_cli_uses_the_shared_launcher_without_a_console_window(self):
        from jobfind import cmd_wireless_ui
        with patch("subprocess.Popen") as launch:
            self.assertEqual(cmd_wireless_ui(None), 0)
        arguments = launch.call_args.args[0]
        self.assertEqual(Path(arguments[5]).name, "start.ps1")
        self.assertEqual(arguments[-2:], ["--page", "wireless"])
        self.assertEqual(launch.call_args.kwargs["creationflags"], subprocess.CREATE_NO_WINDOW)


if __name__ == "__main__":
    unittest.main()
