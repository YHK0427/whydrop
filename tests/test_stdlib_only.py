import ast
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "whydrop"
PKGS = [SRC / name for name in ("proto", "reflector", "measure", "analysis")]  # web/ may use the extra


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


def test_web_bus_is_stdlib_only():
    """The agent imports the bus even without the web extra."""
    import ast as _ast
    tree = _ast.parse((SRC / "web" / "bus.py").read_text(encoding="utf-8"))
    mods = {n.names[0].name.split(".")[0] for n in _ast.walk(tree) if isinstance(n, _ast.Import)}
    mods |= {n.module.split(".")[0] for n in _ast.walk(tree) if isinstance(n, _ast.ImportFrom) and n.module}
    assert mods <= set(sys.stdlib_module_names)
