import sys
from pathlib import Path

SKIP_DIRS = {".git", ".github", ".superpowers", ".venv", "node_modules", ".pytest_cache"}
EXEMPT = ("LICENSE", "CHANGELOG.md")


def missing_pairs(root: Path) -> list[str]:
    files = set()
    for p in root.rglob("*.md"):
        rel = p.relative_to(root)
        if SKIP_DIRS & set(rel.parts) or rel.name.startswith(EXEMPT):
            continue
        files.add(rel.as_posix())
    missing = []
    for f in files:
        pair = f[:-6] + ".md" if f.endswith(".ko.md") else f[:-3] + ".ko.md"
        if pair not in files:
            missing.append(pair)
    return sorted(missing)


if __name__ == "__main__":
    missing = missing_pairs(Path(__file__).resolve().parent.parent)
    for m in missing:
        print(f"missing: {m}")
    sys.exit(1 if missing else 0)
