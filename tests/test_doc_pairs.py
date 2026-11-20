from pathlib import Path

from check_doc_pairs import missing_pairs

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_doc_pairs(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/a.md").write_text("x")
    (tmp_path / "LICENSE").write_text("x")
    (tmp_path / "CHANGELOG.md").write_text("x")
    assert missing_pairs(tmp_path) == ["docs/a.ko.md"]
    (tmp_path / "docs/a.ko.md").write_text("x")
    assert missing_pairs(tmp_path) == []


def test_repo_doc_pairs():
    assert missing_pairs(REPO_ROOT) == []
