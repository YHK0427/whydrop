**English** | [한국어](CONTRIBUTING.ko.md)

# Contributing

Thanks for helping. The most useful thing you can send is a **wrong diagnosis**: a drop whydrop explained badly, or one it missed. Open an issue with the *Wrong diagnosis* template and attach the drop's bug report (Drops → the drop → *Bug report (JSON, public view)*); it uses the public view, so addresses are already removed. Read it before you attach it anyway.

## Development

```sh
git clone https://github.com/YHK0427/whydrop && cd whydrop
uv sync --all-extras
uv run pytest -q                                  # unit, integration, web
uv run playwright install chromium && uv run pytest -q -m ui tests/ui   # the dashboard in a real browser
uv run whydrop agent                              # basic mode on this machine
```

Python 3.11–3.14. The agent, the probes and the reflector use the standard library only; the dashboard adds FastAPI. Please keep it that way — a new runtime dependency needs a strong reason.

## Changing a rule

Every threshold is in `src/whydrop/analysis/constants.py`. Before changing one, replay real data:

```sh
uv run whydrop replay path/to/whydrop.db --set LAN_MISSES=3
```

and say in the pull request how the incident count changed and why the removed or added drops were wrong or right. A rule change without a test that fails before it is unlikely to be merged.

## Pull requests

- Tests first, and `uv run pytest -q` green, UI tests included if you touched `src/whydrop/web/static`.
- Every Markdown document has an English `X.md` and a Korean `X.ko.md`; change both (`scripts/check_doc_pairs.py` checks that the pair exists). Not comfortable writing one of the languages? Say so in the PR and it'll be filled in.
- Never put a real address, Wi-Fi name, MAC or BSSID in a test, a doc or a screenshot. Use the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). `scripts/scan_public.py` and a test check the docs.
- No secrets in files: `WHYDROP_SECRET` and `WHYDROP_UI_TOKEN` come from the environment only.

## Code style

Small functions, names that say what a thing is, comments that say *why*. Every cause string says "likely".
