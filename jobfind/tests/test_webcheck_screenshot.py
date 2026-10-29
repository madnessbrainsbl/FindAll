"""Exercise the Windows Web-Check handler without launching a real browser."""
import shutil
import subprocess
import unittest
from pathlib import Path


class WebCheckScreenshotTests(unittest.TestCase):
    def test_windows_browser_arguments_and_cleanup(self):
        node = shutil.which("node")
        root = Path(__file__).resolve().parents[1]
        if not node or not (root / "third_party/web-check/node_modules/puppeteer-core").is_dir():
            self.skipTest("Web-Check Node dependencies are not installed")
        result = subprocess.run([node, str(root / "tests/webcheck_screenshot.mjs")], cwd=root,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
