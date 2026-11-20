"""docs/protocol(.ko).md byte counts must match the codecs."""
import re
from pathlib import Path

import pytest

from whydrop.proto.wd import WD_LEN
from whydrop.proto.wt import FRAME_LEN, HELLO_LEN, HELLO_OK_LEN, NONCE_LEN, SHORT_LEN

DOCS = Path(__file__).resolve().parents[1] / "docs"
EXPECTED = {"WD": WD_LEN, "NONCE": NONCE_LEN, "HELLO": HELLO_LEN, "HELLO_OK": HELLO_OK_LEN,
            "AUTH_FAIL": SHORT_LEN, "VERSION": SHORT_LEN, "BUSY": SHORT_LEN, "FRAME": FRAME_LEN}
ROW = re.compile(r"^\|\s*`([A-Z_]+)`\s*\|.*\|\s*(\d+) B\s*\|\s*$")


@pytest.mark.parametrize("name", ["protocol.md", "protocol.ko.md"])
def test_doc_sizes_match_code(name):
    sizes = {}
    for line in (DOCS / name).read_text(encoding="utf-8").splitlines():
        m = ROW.match(line)
        if m:
            sizes[m.group(1)] = int(m.group(2))
    assert sizes == EXPECTED
