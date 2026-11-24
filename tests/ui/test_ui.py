"""Dashboard checks in a real browser against the fixture (UI design doc §9, §11): axe-core with zero serious or
critical violations on every screen in both themes and both languages, a complete keyboard path, no console errors,
and Korean wrapping at 360 px without horizontal scroll. Skipped when Playwright's Chromium isn't installed."""
import re
import socket
import threading
import time
from pathlib import Path

import pytest

pw = pytest.importorskip("playwright.sync_api")
pytestmark = pytest.mark.ui
AXE = Path(__file__).with_name("vendor") / "axe.min.js"
SCREENS = {"now": "#/", "drops": "#/drops", "drop": "#/drop/1", "nat": "#/nat", "protocol": "#/protocol", "network": "#/network"}


TOKEN = "uiTest_token_1234567890"


def _serve(tmp_path_factory, token=None):
    import uvicorn

    from fixture import build
    from whydrop.web.app import create_app
    from whydrop.web.bus import Bus
    db = tmp_path_factory.mktemp("ui") / "w.db"
    box = {}
    th = threading.Thread(target=lambda: box.update(st=build(db, "precision")))  # Playwright owns this thread's loop
    th.start()
    th.join()
    st = box["st"]
    app = create_app(db, Bus(), token=token, allowed_hosts=["127.0.0.1"], public_default=False,
                     status=lambda: {**st, "now_ms": int(time.time() * 1000)}, nat_run=lambda: True)
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    threading.Thread(target=server.run, kwargs={"sockets": [s]}, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return f"http://127.0.0.1:{port}", server


@pytest.fixture(scope="module")
def base(tmp_path_factory):
    url, server = _serve(tmp_path_factory)
    yield url
    server.should_exit = True


@pytest.fixture(scope="module")
def base_token(tmp_path_factory):
    url, server = _serve(tmp_path_factory, TOKEN)
    yield url
    server.should_exit = True


@pytest.fixture(scope="module")
def browser():
    with pw.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # browsers not installed (e.g. a plain CI job)
            pytest.skip(f"chromium not available: {e}")
        yield b
        b.close()


def open_page(browser, base, route, theme="light", lang="en", width=1280):
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=theme,
                              bypass_csp=True)   # only so axe can be injected; the CSP itself is tested elsewhere
    ctx.add_init_script(f"localStorage.setItem('whydrop.lang','{lang}')")
    page = ctx.new_page()
    errors = []
    page.on("console", lambda m: m.type == "error" and errors.append(m.text))
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{base}/{route}")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(400)
    return ctx, page, errors


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("lang", ["en", "ko"])
def test_axe_no_serious_violations(browser, base, theme, lang):
    bad = {}
    for name, route in SCREENS.items():
        ctx, page, errors = open_page(browser, base, route, theme, lang)
        page.add_script_tag(path=str(AXE))
        res = page.evaluate("async () => (await axe.run(document, {resultTypes: ['violations']})).violations"
                            ".filter(v => v.impact === 'serious' || v.impact === 'critical')"
                            ".map(v => v.id + ': ' + v.nodes.slice(0, 2).map(n => n.target.join(' ')).join(' | '))")
        if res or errors:
            bad[name] = res + errors
        ctx.close()
    assert not bad, bad


def test_keyboard_path_reaches_every_control(browser, base):
    ctx, page, _ = open_page(browser, base, "#/")
    seen = []
    for _ in range(40):
        page.keyboard.press("Tab")
        seen.append(page.evaluate("() => { const e = document.activeElement; return (e.getAttribute('aria-label') || e.textContent || '').trim().slice(0, 30) }"))
    ctx.close()
    text = " | ".join(seen)
    for must in ("Drops", "NAT timeouts", "Internet line", "Last 1 h", "Start a 2-minute test", "Table"):
        assert must in text, (must, text)


def test_korean_phone_width_has_no_horizontal_scroll(browser, base):
    for name, route in SCREENS.items():
        ctx, page, _ = open_page(browser, base, route, lang="ko", width=360)
        overflow = page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
        ctx.close()
        assert overflow <= 1, (name, overflow)


def test_real_csp_and_token_flow(browser, base_token):
    """No CSP bypass here: the page must work under its own CSP, take the token from the link, drop it from the URL,
    and use it for the API and the WebSocket."""
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    errors = []
    page.on("console", lambda m: m.type == "error" and errors.append(m.text))
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{base_token}/?token={TOKEN}#/")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(600)
    assert "token" not in page.url
    assert page.locator("h1.status").inner_text()
    assert page.evaluate("() => sessionStorage.getItem('whydrop.token')") == TOKEN
    page.wait_for_function("() => true")
    page.goto(f"{base_token}/#/drop/1")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(400)
    assert "dropped" in page.locator("h1.headline").inner_text() and not errors, errors
    ctx.close()


def test_public_view_charts_are_placed_at_now(browser, base):
    """Public charts carry seconds relative to now (no absolute times); the lanes put them back on the clock."""
    ctx, page, errors = open_page(browser, base, "?public=1#/")
    got = page.evaluate("""async () => {
        const { series } = await import('/components/lanes.js');
        const c = await (await fetch('/api/chart?public=1')).json();
        const s = series(c, 'precision');
        return { abs: 'x' in c, n: c.x_rel.length, last: s.x[s.x.length - 1], now: Date.now() / 1000 };
    }""")
    ctx.close()
    assert not got["abs"] and got["n"] > 0 and abs(got["now"] - got["last"]) < 600, got
    assert not errors, errors


def test_no_screen_prints_null_or_undefined(browser, base):
    """Seen on the home server before the first NAT test finished: the NAT page showed a bare 'null' under its
    empty message (a null handed to replaceChildren becomes text)."""
    import json as _json
    import re
    for name, route in SCREENS.items():
        ctx, page, _ = open_page(browser, base, route)
        assert not re.search(r"\b(null|undefined|NaN)\b", page.inner_text("main")), name
        ctx.close()
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    page.route("**/api/nat*", lambda r: r.fulfill(content_type="application/json",
                                                 body=_json.dumps({"running": None, "last_run": None, "results": []})))
    page.goto(f"{base}/#/nat")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(400)
    text = page.inner_text("main")
    ctx.close()
    assert "null" not in text, text


def test_point_event_drop_page_has_no_null_and_no_repeated_evidence(browser, base):
    """QA on the real DB: a point event (no protocol paragraph) printed 'null' on its drop page, and its evidence listed
    cause_interval_s next to interval_s."""
    import json as _json

    def strip_protocol(route):
        body = _json.loads(route.fetch().text())
        ev = _json.loads(body["evidence_json"]) if body.get("evidence_json") else body.get("evidence", {})
        ev["protocol"] = ""
        ev["interval_s"] = ev["cause_interval_s"] = 600
        if body.get("evidence_json"):
            body["evidence_json"] = _json.dumps(ev)
        else:
            body["evidence"] = ev
        route.fulfill(content_type="application/json", body=_json.dumps(body))
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    page.route(re.compile(r".*/api/incidents/1(\?.*)?$"), strip_protocol)
    page.goto(f"{base}/#/drop/1")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(600)
    text = page.inner_text("main")
    ctx.close()
    assert "null" not in text and "cause_interval_s" not in text, text[-600:]


@pytest.mark.parametrize("lang,words", [("en", "Home network slowed down for"), ("ko", "집 안 네트워크가")])
def test_in_home_verdict_draws_the_break_before_the_router(browser, base, lang, words):
    """Demo incident 38: the verdict was in-home queueing, but the headline said the internet line dropped and the
    path drew the line cut. The delay is before the router, and it is slowness, not a cut."""
    import json as _json

    def in_home(route):
        body = _json.loads(route.fetch().text())
        body.update(primary_cause="R7", cause_final="R7",
                    tags_json=_json.dumps({"segments": ["line"], "tags": [], "chain": [], "point": None}),
                    evidence_json=_json.dumps({"label": "In-home queueing (likely)", "cause": "R7", "cause_where": "home"}))
        route.fulfill(content_type="application/json", body=_json.dumps(body))
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    ctx.add_init_script(f"localStorage.setItem('whydrop.lang','{lang}')")
    page = ctx.new_page()
    page.route(re.compile(r".*/api/incidents/1(\?.*)?$"), in_home)
    page.goto(f"{base}/#/drop/1")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(600)
    head = page.inner_text("h1.headline")
    nodes = page.eval_on_selector_all("main svg g.node", "gs => gs.map(g => [g.getAttribute('aria-label'), g.getAttribute('class')])")
    broken = page.locator("main svg .cable.broken").count()
    ctx.close()
    assert words in head, head
    assert broken == 0, nodes
    assert [c.strip() for _, c in nodes] == ["node", "node warn", "node", "node", "node"], nodes   # Wi-Fi is the hop


def test_protocol_story_is_in_the_page_language(browser, base):
    """The Korean drop page printed the "In protocol terms" paragraph in English."""
    texts = {}
    for lang in ("en", "ko"):
        ctx, page, errors = open_page(browser, base, "#/drop/1", lang=lang)
        texts[lang] = page.inner_text("main p.protocol >> nth=-1")
        main = page.inner_text("main")
        ctx.close()
        assert not errors, errors
    assert texts["en"].startswith("UDP: sent seq 1201–1660") and "all lost upstream" in texts["en"]
    assert "모두 올라가는 길에서" in texts["ko"], texts["ko"]
    assert "upload" not in main and "업로드" in main                      # evidence values too, not only the paragraph
    english = re.findall(r"[A-Za-z]{4,} [a-z]{3,}", main)   # the whole Korean page: no English sentence anywhere
    assert not english, english


@pytest.fixture(scope="module")
def static_site(tmp_path_factory):
    """The public demo as `whydrop export-static` writes it, served as plain files (GitHub Pages)."""
    import functools
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

    from fixture import build
    from whydrop.web.static_export import export_static
    d = tmp_path_factory.mktemp("demo")
    def make():   # in a thread: Playwright owns this thread's event loop
        export_static(d / "w.db", d / "site", None, build(d / "w.db", "precision")["now_ms"], {"mode": "precision"})
    th = threading.Thread(target=make)
    th.start()
    th.join()
    quiet = type("Q", (SimpleHTTPRequestHandler,), {"log_message": lambda *a: None})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(quiet, directory=str(d / "site")))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.mark.parametrize("lang", ["en", "ko"])
def test_static_protocol_page_says_packets_are_not_in_the_demo(browser, static_site, lang):
    """The demo's protocol page said packets fill in once precision mode is on (they never do there), with a pause
    button that did nothing and an empty table."""
    ctx, page, errors = open_page(browser, static_site, "#/protocol", lang=lang)
    text = page.inner_text("main")
    buttons, tables = page.locator("main button").count(), page.locator("main table").count()
    href = page.get_attribute("main a", "href")
    ctx.close()
    assert not errors, errors
    assert buttons == 0 and tables == 0, text
    assert ("no real packets" if lang == "en" else "실제 패킷을 넣지 않았어요") in text, text
    assert href.endswith("docs/protocol.md" if lang == "en" else "docs/protocol.ko.md")


def test_nat_labels_do_not_overlap(browser, base):
    """With the home router's results the UDP label sat on the TCP line (both end at 'forgotten')."""
    import json as _json
    udp = [(10, 1), (20, 1), (30, 1), (45, 1), (60, 1), (90, 1), (120, 0), (180, 0), (300, 0), (600, 0)]
    tcp = [(60, 1), (300, 1), (600, 0), (1200, 0), (1800, 0), (3600, 0)]
    rows = [{"proto": p, "delay_s": d, "alive": a} for p, xs in (("udp", udp), ("tcp", tcp)) for d, a in xs]

    def nat(route):
        body = _json.loads(route.fetch().text())
        body["results"] = rows
        route.fulfill(content_type="application/json", body=_json.dumps(body))
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    page = ctx.new_page()
    page.route(re.compile(r".*/api/nat(\?.*)?$"), nat)
    page.goto(f"{base}/#/nat")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(400)
    hits = page.evaluate("""() => {
      const svg = document.querySelector('main svg[role=img]');
      const labels = [...svg.querySelectorAll('text')].filter(x => ['UDP', 'TCP'].includes(x.textContent));
      const paths = [...svg.querySelectorAll('path')];
      const out = [];
      for (const lab of labels) {
        const b = lab.getBBox();
        const mine = lab.textContent === 'UDP' ? 'var(--udp)' : 'var(--tcp)';
        for (const p of paths.filter(p => p.getAttribute('stroke') !== mine))
          for (let x = b.x; x <= b.x + b.width; x += 1) for (let y = b.y; y <= b.y + b.height; y += 1) {   // 1 px: the line is 2.5
            const pt = svg.createSVGPoint(); pt.x = x; pt.y = y;
            if (p.isPointInStroke(pt)) { out.push([lab.textContent, x, y]); x = Infinity; break; }
          }
        for (const o of labels) if (o !== lab) { const c = o.getBBox();
          if (b.x < c.x + c.width && c.x < b.x + b.width && b.y < c.y + c.height && c.y < b.y + b.height) out.push([lab.textContent, 'label']); }
      }
      return [labels.length, out];
    }""")
    ctx.close()
    assert hits[0] == 2 and hits[1] == [], hits


BROKEN_WORDS = """() => {   // every space-separated word in headings, headers and sentences sits on one line
  const out = [];
  for (const el of document.querySelectorAll('main h1, main h2, main th, main p:not(.hex)')) {
    const walk = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    for (let n = walk.nextNode(); n; n = walk.nextNode()) {
      for (const m of n.textContent.matchAll(/\S+/g)) {
        const r = document.createRange(); r.setStart(n, m.index); r.setEnd(n, m.index + m[0].length);
        const tops = new Set([...r.getClientRects()].filter(b => b.width > 0).map(b => Math.round(b.top)));
        if (tops.size > 1) out.push(m[0]);
      }
    }
  }
  return out;
}"""


@pytest.mark.parametrize("width", [390, 1280])
def test_korean_headline_does_not_break_inside_a_word(browser, base, width):
    """Korean wrapped inside words: the headline's "(추정)" split as "(추 / 정)", the drops header "길이" as "길 / 이"."""
    broken = {}
    for route in ("#/", "#/drops", "#/drop/1", "#/nat", "#/network"):
        ctx, page, _ = open_page(browser, base, route, lang="ko", width=width)
        if words := page.evaluate(BROKEN_WORDS):
            broken[route] = words
        ctx.close()
    assert not broken, broken

