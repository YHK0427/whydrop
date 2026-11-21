"""Screenshots of every screen × {light, dark} × {1280, 360} × {en, ko} into artifacts/screens/ (for a person to review),
plus console errors. `python tests/ui/shoot.py http://127.0.0.1:8799 [screen ...]`."""
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

SCREENS = {"now": "#/", "drops": "#/drops", "drop": "#/drop/1", "nat": "#/nat", "protocol": "#/protocol", "network": "#/network"}
OUT = Path("artifacts/screens")


def shoot(base: str, only=None, themes=("light", "dark"), widths=(1280, 360), langs=("en", "ko"), query=""):
    OUT.mkdir(parents=True, exist_ok=True)
    errors = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        for lang in langs:
            for theme in themes:
                for w in widths:
                    ctx = b.new_context(viewport={"width": w, "height": 900}, color_scheme=theme, locale=lang)
                    ctx.add_init_script(f"localStorage.setItem('whydrop.lang','{lang}')")
                    page = ctx.new_page()
                    page.on("console", lambda m: m.type == "error" and errors.append(m.text))
                    page.on("pageerror", lambda e: errors.append(str(e)))
                    for name, route in SCREENS.items():
                        if only and name not in only:
                            continue
                        page.goto(f"{base}/{query}{route}")
                        page.wait_for_load_state("networkidle")
                        page.wait_for_timeout(600)
                        page.screenshot(path=str(OUT / f"{name}-{lang}-{theme}-{w}.png"), full_page=True)
                    ctx.close()
        b.close()
    return errors


if __name__ == "__main__":
    errs = shoot(sys.argv[1], sys.argv[2:] or None)
    print("console errors:", len(errs))
    for e in sorted(set(errs))[:20]:
        print(" ", e[:200])
