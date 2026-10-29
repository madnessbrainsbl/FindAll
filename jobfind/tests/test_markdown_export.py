"""Synthetic portable Markdown and non-destructive vault exports."""
import json
import tempfile
import unittest
from pathlib import Path

from jf import markdown_export, evidence_graph


class MarkdownExportTest(unittest.TestCase):
    def data(self, root):
        path = Path(root) / "reports" / "dossier.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        result = {"query": "Тест / .. / CON", "kind": "person", "observed_at": "2026-10-03T00:00:00+00:00",
            "report_json": str(path), "sections": {"web": [{"title": "Alex | Test", "url": "https://example.org/a", "source": "Web", "snippet": "Public evidence"}]},
            "source_checks": [{"source": "Web", "state": "ok", "count": 1}],
            "ai_analysis": {"answer": "Нашлась публичная страница.", "claims": [{"statement": "Page observed", "quote": "Public evidence", "source_url": "https://example.org/a"}]}}
        path.write_text(json.dumps(result), encoding="utf-8")
        result["relationship_graph"] = evidence_graph.build_graph(result)
        return result

    def test_default_markdown_and_safe_content(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.data(root)
            result["sections"]["web"].append({"title": "<script>x</script>", "url": "javascript:alert(1)"})
            info = markdown_export.save(result)
            text = Path(info["markdown"]).read_text(encoding="utf-8")
            self.assertIn("Нашлась", text)
            self.assertIn("https://example.org/a", text)
            self.assertNotIn("javascript:", text)
            self.assertNotIn("<script>", text)
            self.assertIn("Alex \\| Test", text)
            self.assertEqual(Path(info["markdown"]).name, "dossier.md")
            self.assertEqual(result["exported_paths"]["markdown"], info["markdown"])

    def test_vault_versions_never_overwrite_user_notes(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.data(root)
            vault = Path(root) / "vault"
            vault.mkdir()
            note = vault / "index.md"
            note.write_text("user note", encoding="utf-8")
            first = markdown_export.save(result, vault)
            second = markdown_export.save(result, vault)
            self.assertNotEqual(first["obsidian_directory"], second["obsidian_directory"])
            self.assertEqual(note.read_text(encoding="utf-8"), "user note")
            folder = Path(first["obsidian_directory"])
            self.assertTrue(folder.is_relative_to(vault))
            for node in result["relationship_graph"]["nodes"]:
                text = (folder / (node["id"] + ".md")).read_text(encoding="utf-8")
                self.assertIn("[[index|Run index]]", text)
            index = Path(first["obsidian_index"]).read_text(encoding="utf-8")
            self.assertIn("[[" + result["relationship_graph"]["root_id"] + "]]", index)
            self.assertTrue((folder / "dossier.json").is_file())

    def test_invalid_vault_path_preserves_file(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.data(root)
            vault = Path(root) / "user.md"
            vault.write_text("keep", encoding="utf-8")
            with self.assertRaises(ValueError):
                markdown_export.save(result, vault)
            self.assertEqual(vault.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
