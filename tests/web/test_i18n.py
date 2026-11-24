"""UI strings: identical key sets in EN and KO, every key the code uses exists, causes translated (UI design doc §8)."""
import json
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[2] / "src" / "whydrop" / "web" / "static"


def load(name):
    return json.loads((STATIC / "i18n" / name).read_text(encoding="utf-8"))


def test_key_parity():
    en, ko = load("en.json"), load("ko.json")
    assert set(en) == set(ko), set(en) ^ set(ko)


def test_every_used_key_exists():
    en = load("en.json")
    used = set()
    for js in STATIC.rglob("*.js"):
        if "vendor" in js.parts:
            continue
        used |= set(re.findall(r"\bt\(\s*\"([a-z_]+(?:\.[\w-]+)+)\"", js.read_text(encoding="utf-8")))
    assert len(used) > 80          # the scan really finds the keys
    missing = {k for k in used if k not in en}
    assert not missing, missing


def test_every_cause_text_has_korean():
    from whydrop.analysis import texts
    ko = load("causes.ko.json")
    def strings(v):   # every text in the module, so a new one can't be added without its Korean
        if isinstance(v, str):
            yield v
        elif isinstance(v, (tuple, list)):
            for x in v:
                yield from strings(x)
        elif isinstance(v, dict):
            for x in v.values():
                yield from strings(x)
    server = {s for n, v in vars(texts).items() if n.isupper() for s in strings(v) if s}
    assert server <= set(ko), server - set(ko)
    assert all("추정" in ko[k] for k in server if "likely" in k)


def test_static_shell_served_with_csp():
    from fastapi.testclient import TestClient

    from whydrop.web.app import create_app
    from whydrop.web.bus import Bus
    c = TestClient(create_app(None, Bus(), token=None, allowed_hosts=["testserver"], public_default=False))
    for path in ("/", "/app.js", "/tokens.css", "/i18n/ko.json", "/vendor/uplot/uPlot.esm.js", "/fonts/PretendardVariable.woff2"):
        r = c.get(path)
        assert r.status_code == 200 and "default-src 'self'" in r.headers["content-security-policy"], path


def test_every_finding_kind_has_words_in_both_languages():
    """The My network page lists findings by kind; a kind without words showed as a raw key (target_specific)."""
    import re
    from pathlib import Path
    src = "\n".join(p.read_text(encoding="utf-8") for p in Path("src/whydrop").rglob("*.py"))
    kinds = set(re.findall(r'"finding", now, [^,]+, \{"kind": "(\w+)"', src)) \
        | set(re.findall(r'insert\("findings", kind="(\w+)"', src)) \
        | set(re.findall(r'IncidentChange\("finding", None, "(\w+)"', src))         | set(re.findall(r'standing\("(\w+)"', src))
    assert {"target_specific", "idle_expiry_repeat", "vpn_egress", "secret_mismatch"} <= kinds, kinds   # the scan really finds them
    for lang in ("en", "ko"):
        words = load(f"{lang}.json")
        assert not {k for k in kinds if f"finding.{k}" not in words}, (lang, kinds)
