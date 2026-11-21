"""Dashboard checks in a real browser against the fixture (UI design doc §9, §11): axe-core with zero serious or
critical violations on every screen in both themes and both languages, a complete keyboard path, no console errors,
and Korean wrapping at 360 px without horizontal scroll. Skipped when Playwright's Chromium isn't installed."""
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
    for must in ("Drops", "NAT timeouts", "Internet line", "Last 1 h", "I'm testing now", "Table"):
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
