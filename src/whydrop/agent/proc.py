"""Run a short external command (iw, netsh, ip, route) without ever leaving a child behind."""
import asyncio


async def run_cmd(*args: str, timeout_s: float = 5.0) -> bytes:
    """stdout of the command. On timeout the child is killed and reaped, so a hung `iw` or `netsh` can't pile up
    against the container's pids limit (raises asyncio.TimeoutError)."""
    proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.DEVNULL)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout_s)
        return out
    except BaseException:  # timeout or cancellation
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
        raise
