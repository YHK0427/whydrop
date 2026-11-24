"""Dashboard checks in a real browser against the fixture (UI design doc §9, §11): axe-core with zero serious or
critical violations on every screen in both themes and both languages, a complete keyboard path, no console errors,
and Korean wrapping at 360 px without horizontal scroll. Skipped when Playwright's Chromium isn't installed."""
import json
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


def _serve(tmp_path_factory, token=None, builder=None):
    import uvicorn

    from fixture import build
    from whydrop.web.app import create_app
    from whydrop.web.bus import Bus
    db = tmp_path_factory.mktemp("ui") / "w.db"
    box = {}
    th = threading.Thread(target=lambda: box.update(st=(builder or build)(db, "precision")))  # Playwright owns this thread's loop
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


def open_page(browser, base, route, theme="light", lang="en", width=1280, setup=None, tz=None):
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=theme, timezone_id=tz,
                              bypass_csp=True)   # only so axe can be injected; the CSP itself is tested elsewhere
    ctx.add_init_script(f"localStorage.setItem('whydrop.lang','{lang}')")
    page = ctx.new_page()
    errors = []
    page.on("console", lambda m: m.type == "error" and errors.append(m.text))
    page.on("pageerror", lambda e: errors.append(str(e)))
    if setup:
        setup(page)   # page.route fakes, before the first request
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


@pytest.mark.parametrize("lang", ["ko", "en"])   # en too: a nowrap header once pushed the English drops table out
def test_phone_width_has_no_horizontal_scroll(browser, base, lang):
    for name, route in SCREENS.items():
        ctx, page, _ = open_page(browser, base, route, lang=lang, width=360)
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


@pytest.mark.parametrize("width", [1280, 390])
def test_nat_labels_do_not_overlap(browser, base, width):
    """With the home router's results the UDP label sat on the TCP line (both end at 'forgotten'). On a phone the chart
    was a 640-wide drawing shrunk to fit, so its 12 px text came out at 7 px."""
    import json as _json
    udp = [(10, 1), (20, 1), (30, 1), (45, 1), (60, 1), (90, 1), (120, 0), (180, 0), (300, 0), (600, 0)]
    tcp = [(60, 1), (300, 1), (600, 0), (1200, 0), (1800, 0), (3600, 0)]
    rows = [{"proto": p, "delay_s": d, "alive": a} for p, xs in (("udp", udp), ("tcp", tcp)) for d, a in xs]

    def nat(route):
        body = _json.loads(route.fetch().text())
        body["results"] = rows
        route.fulfill(content_type="application/json", body=_json.dumps(body))
    ctx = browser.new_context(viewport={"width": width, "height": 900})
    page = ctx.new_page()
    page.route(re.compile(r".*/api/nat(\?.*)?$"), nat)
    page.goto(f"{base}/#/nat")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(400)
    hits = page.evaluate("""() => {
      const svg = document.querySelector('main svg[role=img]');
      const labels = [...svg.querySelectorAll('text')].filter(x => ['UDP', 'TCP'].includes(x.textContent));
      const paths = [...svg.querySelectorAll('path, line')];   // the other line, and the x axis
      const out = [];
      for (const lab of labels) {
        const b = lab.getBBox();
        const mine = lab.textContent === 'UDP' ? 'var(--udp)' : 'var(--tcp)';
        for (const p of paths.filter(p => p.getAttribute('stroke') !== mine))
          for (let x = b.x; x <= b.x + b.width; x += 1) for (let y = b.y; y <= b.y + b.height; y += 1) {   // 1 px: the line is 2.5
            const pt = svg.createSVGPoint(); pt.x = x; pt.y = y;
            if (p.isPointInStroke(pt)) { out.push([lab.textContent, x, y]); x = Infinity; break; }
          }
      }
      const texts = [...svg.querySelectorAll('text')];
      texts.forEach((a, i) => texts.slice(i + 1).forEach(o => { const b = a.getBBox(), c = o.getBBox();   // labels and ticks alike
        if (b.x < c.x + c.width && c.x < b.x + b.width && b.y < c.y + c.height && c.y < b.y + b.height) out.push([a.textContent, o.textContent]); }));
      return [labels.length, out, Math.min(...texts.map(x => x.getBoundingClientRect().height))];
    }""")
    ctx.close()
    assert hits[0] == 2 and hits[1] == [] and hits[2] >= 12, hits   # 12 px text renders about 15 px tall


BROKEN_WORDS = r"""() => {   // every space-separated word in headings, headers and sentences sits on one line
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


# ---------- state matrix: loading, API errors, fresh install, one drop, 1000 drops ----------
# Covering set, not the full product: screen i of a state gets AXES[i] (language, theme, width), and the views rotate
# owner / public / static, so each state sees every screen and every value of every axis at least once.
I18N_KEYS = sorted(json.loads((Path(__file__).parents[2] / "src/whydrop/web/static/i18n/en.json").read_text("utf-8")),
                   key=len, reverse=True)
CODE_WORDS = ("Wireshark dissector",)   # a product name, not an English sentence
AXES = [("en", "light", 1280), ("ko", "dark", 390), ("ko", "light", 1280), ("en", "dark", 390), ("ko", "dark", 1280), ("en", "light", 390)]
LONG = "reflector-" + "a" * 150   # an unbroken token (a hostname, a hash) inside a server text


def problems(page, errors, lang, net_errors=False, long_words=False):
    """What every screen is checked for; [] when it is clean."""
    text = page.inner_text("body")
    out = re.findall(r"\b(?:null|undefined|NaN)\b", text)
    out += [k for k in I18N_KEYS if re.search(rf"(?<![\w.]){re.escape(k)}(?![\w.])", text)]   # a raw i18n key
    scroll = page.evaluate("() => document.documentElement.scrollWidth - document.documentElement.clientWidth")
    out += [f"horizontal scroll {scroll}px"] if scroll > 1 else []
    out += [e for e in errors if not (net_errors and e.startswith("Failed to load resource"))]   # the faked failures
    if lang == "ko":
        out += [m for m in re.findall(r"[A-Za-z]{4,} [a-z]{3,}", text) if not any(m in c for c in CODE_WORDS)]
        out += [w for w in page.evaluate(BROKEN_WORDS) if not (long_words and len(w) > 40)]   # 160 letters must break
    return out


def _site(view, base, static_site):
    return (static_site, "") if view == "static" else (base, "?public=1" if view == "public" else "")


@pytest.mark.parametrize("state", ["401", "500", "down"])
def test_api_errors_show_a_plain_error_panel(browser, base, static_site, state):
    """With the agent stopped every screen said "Couldn't load data (server returned ?)" ("data" in English on the
    Korean page); a 500 printed the raw /api/...?from=<epoch> URL twice; the protocol page said "no packets yet"."""
    views = ("owner", "public") if state == "401" else ("owner", "public", "static")   # a static site never asks for a token
    bad = {}
    for i, (name, route) in enumerate(SCREENS.items()):
        lang, theme, width = AXES[i]
        view = views[i % len(views)]
        url, q = _site(view, base, static_site)
        fake = (lambda r: r.abort()) if state == "down" else (lambda r: r.fulfill(status=int(state), body="{}"))
        pattern = "**/data/**" if view == "static" else "**/api/**"
        ctx, page, errors = open_page(browser, url, q + route, theme, lang, width, setup=lambda p: p.route(pattern, fake))
        panel = page.locator("main .banner.bad")
        text = panel.inner_text() if panel.count() else ""
        probs = problems(page, errors, lang, net_errors=True)
        if not (view == "static" and name == "protocol"):   # the demo's protocol page loads nothing
            want = {"401": "token" if lang == "en" else "토큰", "500": "500", "down": "agent"}[state]
            if want not in text or "from=" in text or "?)" in text:   # no epoch query, no unknown code
                probs.append(f"panel: {text!r}")
        if probs:
            bad[f"{name} {view} {lang} {width}"] = probs
        ctx.close()
    assert not bad, bad


def test_loading_state_is_clean_then_fills_in(browser, base):
    """Every screen while its API calls hang, then after they answer."""
    bad = {}
    for i, (name, route) in enumerate(SCREENS.items()):
        lang, theme, width = AXES[i]
        held = []
        ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=theme)
        ctx.add_init_script(f"localStorage.setItem('whydrop.lang','{lang}')")
        page = ctx.new_page()
        errors = []
        page.on("console", lambda m: m.type == "error" and errors.append(m.text))
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.route("**/api/**", lambda r: held.append(r) if held is not None else r.continue_())
        page.goto(f"{base}/{'?public=1' if i % 2 else ''}{route}", wait_until="domcontentloaded")
        page.wait_for_timeout(500)
        probs = problems(page, errors, lang)
        waiting, held = held, None
        for r in waiting:
            r.continue_()
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(400)
        probs += problems(page, errors, lang) + ([] if page.locator("main h1").count() else ["never filled in"])
        if probs:
            bad[name] = probs
        ctx.close()
    assert not bad, bad


@pytest.fixture(scope="module")
def base_empty(tmp_path_factory):
    from fixture import empty
    url, server = _serve(tmp_path_factory, builder=empty)
    yield url
    server.should_exit = True


def test_fresh_install_screens(browser, base_empty):
    """An empty DB with the baseline still learning, owner and public. The public Now page said "press this button"
    with no button on it."""
    bad = {}
    for i, (name, route) in enumerate(SCREENS.items()):
        for view in ("owner", "public"):
            lang, theme, width = AXES[i] if view == "owner" else AXES[(i + 3) % 6]
            ctx, page, errors = open_page(browser, base_empty, ("?public=1" if view == "public" else "") + route, theme, lang, width)
            text = page.inner_text("main")
            probs = problems(page, errors, lang, net_errors=name == "drop")   # drop 1 doesn't exist yet: a 404 panel
            if ("pressing this" in text or "이 버튼" in text) and not page.locator("main button.primary").count():
                probs.append("a hint about a button that isn't there")
            if name == "drop" and "404" not in text:
                probs.append(text)
            if probs:
                bad[f"{name} {view} {lang} {width}"] = probs
            ctx.close()
    assert not bad, bad


@pytest.mark.parametrize("n", [1, 1000])
def test_one_and_many_drops_with_long_strings(browser, base, static_site, n):
    """One drop, and 1000 drops whose label, next step and evidence carry a 160-letter token: the token pushed the
    drops table, the cause filter, the drop page's evidence and the Now page's lists past the screen edge."""
    def fake(page):
        def incidents(route):
            body = json.loads(route.fetch().text())
            one = isinstance(body, dict)
            rows = [body] if one else [dict(body[0], id=i + 1) for i in range(n)]
            for i, r in enumerate(rows):
                if not one and r.get("start_ms") is not None:
                    r["start_ms"] -= i * 600_000
                    r["end_ms"] = r["start_ms"] + 46_000
                if not one and r.get("start_s") is not None:
                    r["start_s"] -= i * 600
                    r["end_s"] = r["start_s"] + 46
                ev = json.loads(r["evidence_json"]) if r.get("evidence_json") else r.setdefault("evidence", {})
                ev.update(label=f"{LONG} (likely)", next_step=LONG, secondary=[LONG])
                if r.get("evidence_json"):
                    r["evidence_json"] = json.dumps(ev)
            route.fulfill(content_type="application/json", body=json.dumps(rows[0] if one else rows))
        page.route(re.compile(r".*/(api/incidents(/1)?|data/incidents_\d+\.json)(\?.*)?$"), incidents)
    bad = {}
    for i, name in enumerate(("now", "drops", "drop", "network")):
        lang, theme, width = AXES[i if n == 1 else i + 2]
        view = ("owner", "public", "static")[i % 3]
        url, q = _site(view, base, static_site)
        ctx, page, errors = open_page(browser, url, q + SCREENS[name], theme, lang, width, setup=fake)
        probs = problems(page, errors, lang, long_words=True)
        if name == "drops" and page.locator("table.drops-table tbody tr").count() != n:
            probs.append("rows")
        if probs:
            bad[f"{name} {view} {lang} {width}"] = probs
        ctx.close()
    assert not bad, bad


def test_every_range_button_shows_the_fixture(browser, base):
    """1 h, 6 h, 24 h and 7 d each draw the fixture's two hours, and the latency table has values."""
    ctx, page, errors = open_page(browser, base, "#/")
    got = {}
    for label in ("6 h", "24 h", "7 d", "Last 1 h"):
        page.get_by_role("button", name=label, exact=True).click()
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(300)
        pressed, canvases = page.locator(".ranges button[aria-pressed=true]").inner_text(), page.locator(".lane canvas").count()
        page.locator(".lane .tablebtn").nth(1).click()   # latency as a table
        got[label] = (pressed, canvases, page.eval_on_selector_all(".lane table.data tbody td:nth-child(2)",
                                                                  "tds => tds.filter(td => /\\d/.test(td.textContent)).length"))
    ctx.close()
    assert not errors and all(p == k and c == 3 and v > 0 for k, (p, c, v) in got.items()), (got, errors)


def test_lanes_handle_null_negative_and_gap_data(browser, base):
    """All-null, negative, gapped and empty series draw without errors or NaN; a table spanning two days dates its rows
    (the 7 d table printed the same clock time for every day)."""
    ctx, page, errors = open_page(browser, base, "#/drops")
    got = page.evaluate("""async () => { const L = await import('/components/lanes.js'); const out = {};
      const now = Math.floor(Date.now() / 1000), n = [null, null, null];
      const cases = { allnull: {x: [now - 30, now - 20, now - 10], up: n, down: n, stream_unknown: n, basic_lost: n, rtt: n, tcp: n},
        negative: {x: [now - 30, now - 20, now - 10], up: [0, 2, 0], down: [-3, 0, -1], stream_unknown: [0, 0, 0], basic_lost: [0, 0, 0], rtt: [-5, 12, 14], tcp: [2, 1, 0]},
        gap: {x: [now - 86400, now - 86390, now], up: [0, 1, 0], down: [0, null, 0], stream_unknown: [0, null, 0], basic_lost: [0, null, 0], rtt: [10, null, 12], tcp: [2, null, 2]},
        none: {x: [], up: [], down: [], stream_unknown: [], basic_lost: [], rtt: [], tcp: []} };
      for (const [k, c] of Object.entries(cases)) for (const mode of ['precision', 'basic']) {
        const el = L.lanes(L.series({step_s: 10, ...c}, mode), {stepS: 10, mode, baseline: 'ready', events: []});
        document.querySelector('main').append(el);
        await new Promise(r => setTimeout(r, 50));
        const canvases = el.querySelectorAll('canvas').length;
        el.querySelectorAll('.tablebtn').forEach(b => b.click());
        out[k + ' ' + mode] = [canvases, el.innerText.match(/\\b(NaN|null|undefined|Infinity)\\b/g),
          [...el.querySelectorAll('table.data tbody td:first-child')].map(td => td.textContent)];
      }
      return out; }""")
    ctx.close()
    assert not errors, errors
    for k, (canvases, nan, _) in got.items():
        assert canvases == (3 if k.endswith("precision") else 2) and not nan, (k, canvases, nan)
    whens = got["gap precision"][2]
    assert whens[0] != whens[2], whens   # 24 h apart: only the date tells them apart


def test_path_draws_every_segment_state(browser, base):
    """ok, unstable, can't see, down and not checked on one live path (where=home is the in-home test above)."""
    ctx, page, errors = open_page(browser, base, "#/drops", lang="ko")
    got = page.evaluate("""async () => { const P = await import('/components/path.js');
      const st = {segments: {host_net: 'up', wifi: 'up', lan: 'unobservable', line: 'down', dns: 'unknown'}, link: 'wifi'};
      const el = P.pathDiagram(P.hops(st, new Set(['wifi'])), {onPick: () => {}});
      document.querySelector('main').append(el);
      return [[...el.querySelectorAll('g.node')].map(g => [g.getAttribute('class').trim(), g.querySelector('.state').textContent]),
              [...el.querySelectorAll('line.cable')].map(c => c.getAttribute('class')), el.querySelector('.why')?.textContent] }""")
    ctx.close()
    assert got[0] == [["node", "✓ 정상"], ["node warn", "! 불안정"], ["node unknown", "? 볼 수 없음"], ["node down", "✕ 끊김"],
                      ["node unknown", "– 확인 안 함"]], got
    assert got[1] == ["cable", "cable unknown", "cable broken", "cable unknown"] and "공유기" in got[2] and not errors, got


def test_strip_has_ten_squares_per_second(browser, base):
    ctx, page, errors = open_page(browser, base, "#/drop/1", width=390)
    rows, secs, squares, ups, up_rows = page.evaluate("""async () => { const r = await (await fetch('/api/incidents/1/strip')).json();
      return [r.length, (r[r.length - 1].ts_ms - r[0].ts_ms + 100) / 1000, document.querySelectorAll('.strip i').length,
              document.querySelectorAll('.strip i.up').length, r.filter(x => x.dir === 'up').length] }""")
    ctx.close()
    assert squares == rows == 10 * secs and ups == up_rows > 0 and not errors, (rows, secs, squares, ups, up_rows, errors)


@pytest.mark.parametrize("tz,hours,lang,want", [("UTC", 0, "en", ["23:58:59", "23:58 today (UTC)", "0 s", "36 h", "3 d"]),
                                                ("Asia/Seoul", 9, "ko", ["08:58:59", "오늘 08:58 (GMT+9)", "0초", "36시간", "3일"])])
def test_times_are_24_hour_in_the_browser_zone(browser, base, tz, hours, lang, want):
    from datetime import datetime, timedelta, timezone
    ctx, page, errors = open_page(browser, base, "#/drops", lang=lang, tz=tz)
    got = page.evaluate("async () => { const L = await import('/lib.js'); const at = Date.UTC(2026, 10, 24, 23, 58, 59);"
                        " return [L.clock(at), L.when(at, at + 60000), L.dur(0), L.dur(1.5 * 86400), L.dur(3 * 86400)] }")
    cell = page.inner_text("table.drops-table tbody td >> nth=0")
    start = max(page.evaluate("async () => (await (await fetch('/api/incidents?from=0')).json()).map(r => r.start_ms)"))
    ctx.close()
    assert got == want and not errors, (got, errors)
    assert datetime.fromtimestamp(start / 1000, timezone(timedelta(hours=hours))).strftime("%H:%M") in cell, cell


@pytest.mark.parametrize("lang", ["en", "ko"])
def test_keyboard_reaches_every_control_with_a_ring(browser, base, lang):
    """Tab reaches every link, button, select and path node on every screen, each with a visible focus ring. The skip
    link said "Skip to content" on the Korean page."""
    bad = {}
    for i, (name, route) in enumerate(SCREENS.items()):
        ctx, page, _ = open_page(browser, base, route, lang=lang, width=(1280, 390)[i % 2])
        total = page.evaluate("() => document.querySelectorAll('a[href], button:not([disabled]), select, [tabindex=\"0\"]').length")
        noring = []
        for _ in range(total + 2):
            page.keyboard.press("Tab")
            el = page.evaluate("""() => { const e = document.activeElement; if (e === document.body) return null;
              e.dataset.reached = '1';
              if (e.tagName === 'g') return [e.getAttribute('aria-label'), getComputedStyle(e.querySelector('circle')).strokeWidth === '4px'];
              const s = getComputedStyle(e); return [e.textContent.trim().slice(0, 20), s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) >= 2] }""")
            if el and not el[1]:
                noring.append(el[0])
        missed = page.evaluate("() => [...document.querySelectorAll('a[href], button:not([disabled]), select, [tabindex=\"0\"]')]"
                               ".filter(e => !e.dataset.reached).map(e => e.outerHTML.slice(0, 60))")
        skip = page.inner_text("a.sr")
        ctx.close()
        if noring or missed or (lang == "ko" and re.search("[A-Za-z]{4}", skip)):
            bad[name] = (noring, missed, skip)
    assert not bad, bad


def test_language_theme_and_table_toggles(browser, base):
    ctx, page, errors = open_page(browser, base, "#/")
    bg = lambda: page.evaluate("() => [document.documentElement.dataset.theme || 'system', getComputedStyle(document.body).backgroundColor]")
    themes = []
    for label in ("Theme: system", "Theme: light", "Theme: dark"):
        page.click(f"text={label}")
        themes.append(bg())
    btn = page.locator(".lane .tablebtn").first
    btn.click()
    as_table = (btn.get_attribute("aria-pressed"), page.locator(".lane").first.locator("table").count())
    btn.click()
    as_chart = (btn.get_attribute("aria-pressed"), page.locator(".lane").first.locator("canvas").count())
    page.click("text=한국어")
    page.wait_for_timeout(400)
    ko = (page.evaluate("() => [document.documentElement.lang, localStorage.getItem('whydrop.lang')]"), page.locator("nav a").first.inner_text())
    ctx.close()
    assert [t for t, _ in themes] == ["light", "dark", "system"] and themes[0][1] != themes[1][1], themes
    assert as_table == ("true", 1) and as_chart == ("false", 1) and ko == (["ko", "ko"], "지금") and not errors, (as_table, as_chart, ko, errors)


@pytest.mark.parametrize("lang,seen,ruled", [("ko", "공유기 확인: 11번 중 11번 응답, 평소 3 ms, 최대 412 ms", "회선 단절 아님"),
                                            ("en", "Router check: 11 of 11 answered, usually 3 ms, up to 412 ms", "Not a line outage")])
def test_a_verdict_shows_its_measurements_instead_of_likely(browser, base, lang, seen, ruled):
    """Owner feedback: '(likely)' on every verdict reads as a guess. The drop page now shows what was measured and
    which causes it rules out, and the headline drops the suffix."""
    import json as _json

    def with_facts(route):
        body = _json.loads(route.fetch().text())
        ev = {"label": "In-home queueing (likely)", "cause": "R7", "cause_where": "home",
              "facts": [{"k": "dur", "dur": 8, "segs": ["line"]}, {"k": "gw", "sent": 11, "ok": 11, "lost": 0, "late": 0, "base": 3, "peak": 412},
                        {"k": "line", "sent": 24, "ok": 0, "late": 24, "lost": 0, "peak": None},
                        {"k": "tcp", "stall": 3.03, "retrans": 1, "rto_lo": 0.22, "rto_hi": 5.79, "rst": False}],
              "ruled_out": [{"k": "router", "ok": 11, "sent": 11, "crossed": 24}, {"k": "line_late", "answered": 24, "late": 24, "sent": 24}, {"k": "ip"}]}
        body.update(primary_cause="R7", cause_final="R7", evidence_json=_json.dumps(ev),
                    tags_json=_json.dumps({"segments": ["line"], "tags": [], "chain": [], "point": None}))
        route.fulfill(content_type="application/json", body=_json.dumps(body))
    ctx = browser.new_context(viewport={"width": 1280, "height": 900})
    ctx.add_init_script(f"localStorage.setItem('whydrop.lang','{lang}')")
    page = ctx.new_page()
    page.route(re.compile(r".*/api/incidents/1(\?.*)?$"), with_facts)
    page.goto(f"{base}/#/drop/1")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(600)
    head = page.inner_text("h1.headline")
    why = page.inner_text("main section.why")
    main = page.inner_text("main")
    ctx.close()
    assert "(추정)" not in head and "(likely)" not in head
    assert seen in why and ruled in why and ("RST 없음" in why if lang == "ko" else "no RST" in why)
    assert not re.search(r"\b(fact|ruled|why)\.[a-z_]+", main), main
