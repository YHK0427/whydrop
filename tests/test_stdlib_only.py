import ast
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "whydrop"
PKGS = [SRC / name for name in ("proto", "reflector", "measure")]


def imported_top_level_modules(pkgs):
    found = set()
    for pkg in pkgs:
        for path in pkg.rglob("*.py") if pkg.is_dir() else []:
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Import):
                    found.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    found.add(node.module.split(".")[0])
    return sorted(found)


def test_stdlib_only():
    bad = [m for m in imported_top_level_modules(PKGS) if m not in sys.stdlib_module_names and m != "whydrop"]
    assert bad == []
