import asyncio
import sys

import pytest

from whydrop.agent import proc


def test_timeout_kills_the_child(monkeypatch):
    spawned = []
    real = asyncio.create_subprocess_exec

    async def spy(*a, **k):
        p = await real(*a, **k)
        spawned.append(p)
        return p
    monkeypatch.setattr(proc.asyncio, "create_subprocess_exec", spy)
    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(proc.run_cmd(sys.executable, "-c", "import time; time.sleep(30)", timeout_s=0.5))
    assert spawned[0].returncode is not None  # killed and reaped, not left running


def test_output_returned():
    assert asyncio.run(proc.run_cmd(sys.executable, "-c", "print('hi')")).strip() == b"hi"
