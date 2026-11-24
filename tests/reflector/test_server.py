import asyncio
import logging
import socket

from whydrop.cli import main
from whydrop.proto.wd import WdPacket, WdType, decode, encode
from whydrop.reflector.server import run_reflector

SECRET = "a" * 32


def test_missing_secret_exit_2(monkeypatch, capsys):
    monkeypatch.delenv("WHYDROP_SECRET", raising=False)
    assert main(["reflector"]) == 2
    assert "WHYDROP_SECRET" in capsys.readouterr().err


def test_example_secret_exit_2(monkeypatch, capsys):
    monkeypatch.setenv("WHYDROP_SECRET", "REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES")
    assert main(["reflector"]) == 2
    assert "REPLACE_WITH" not in capsys.readouterr().err


def test_serves_logs_and_stops(tmp_path, caplog):
    async def scenario():
        stop = asyncio.Event()
        ready = asyncio.get_running_loop().create_future()
        task = asyncio.create_task(run_reflector(
            host="127.0.0.1", port=0, state_dir=tmp_path, enable_7500=False,
            env={"WHYDROP_SECRET": SECRET}, stop=stop, on_ready=lambda u, t: ready.set_result((u, t))))
        udp_port, tcp_port = await asyncio.wait_for(ready, 5)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(encode(WdPacket(WdType.PROBE, 1, 1, 0), SECRET.encode()), ("127.0.0.1", udp_port))
        echo = await asyncio.to_thread(s.recv, 100)
        s.close()
        _, w = await asyncio.open_connection("127.0.0.1", tcp_port)  # TCP side listening too
        w.close()
        stop.set()
        await asyncio.wait_for(task, 5)
        return decode(echo, SECRET.encode())

    with caplog.at_level(logging.INFO):
        p = asyncio.run(scenario())
    assert p.type == WdType.ECHO and p.recv_count == 1
    assert (tmp_path / "tombstones.json").exists()
    assert "listening" in caplog.text and SECRET not in caplog.text


def test_port_in_use_one_line_error(monkeypatch, capsys, tmp_path):
    import socket as s
    monkeypatch.setenv("WHYDROP_SECRET", SECRET)
    busy = s.socket(s.AF_INET, s.SOCK_DGRAM)
    busy.bind(("127.0.0.1", 0))
    port = busy.getsockname()[1]
    try:
        assert main(["reflector", "--host", "127.0.0.1", "--port", str(port), "--state-dir", str(tmp_path)]) == 1
    finally:
        busy.close()
    err = capsys.readouterr().err
    assert "failed to start" in err and "Traceback" not in err

async def _start(tmp_path, enable_7500=False):
    stop = asyncio.Event()
    ready = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(run_reflector(
        host="127.0.0.1", port=0, state_dir=tmp_path, enable_7500=enable_7500,
        env={"WHYDROP_SECRET": SECRET}, stop=stop, on_ready=lambda u, t: ready.set_result((u, t))))
    udp_port, tcp_port = await asyncio.wait_for(ready, 5)
    return stop, task, udp_port, tcp_port


async def _probe(port, seq, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(encode(WdPacket(WdType.PROBE, 9, seq, 0), SECRET.encode()), ("127.0.0.1", port))
        return await asyncio.to_thread(s.recv, 100)
    except TimeoutError:
        return None
    finally:
        s.close()


def test_stop_flushes_tombstones_so_a_restart_rejects_replays(tmp_path):
    async def scenario():
        stop, task, udp_port, _ = await _start(tmp_path)
        assert await _probe(udp_port, 5) is not None
        stop.set()  # before the first periodic flush: only the stop-time flush can save seq 5
        await asyncio.wait_for(task, 5)
        stop, task, udp_port, _ = await _start(tmp_path)
        replayed, fresh = await _probe(udp_port, 5, timeout=0.5), await _probe(udp_port, 6)
        stop.set()
        await asyncio.wait_for(task, 5)
        return replayed, fresh

    replayed, fresh = asyncio.run(scenario())
    assert replayed is None and decode(fresh, SECRET.encode()).seq == 6


def test_disk_full_keeps_serving(tmp_path, monkeypatch, caplog):
    import errno

    import whydrop.reflector.server as server
    from whydrop.reflector.replay import Tombstones

    def full(self, entries):
        raise OSError(errno.ENOSPC, "No space left on device")
    monkeypatch.setattr(Tombstones, "write", full)
    monkeypatch.setattr(server, "FLUSH_EVERY_S", 0.05)

    async def scenario():
        stop, task, udp_port, _ = await _start(tmp_path)
        await asyncio.sleep(0.3)  # several failed periodic flushes
        echo = await _probe(udp_port, 1)
        stop.set()
        await asyncio.wait_for(task, 5)  # the failed stop-time flush must not raise either
        return echo

    with caplog.at_level(logging.WARNING):
        assert asyncio.run(scenario()) is not None
    assert caplog.text.count("could not write tombstones") >= 2


def test_enable_7500_reaches_the_tcp_side(tmp_path):
    from whydrop.proto.wt import Hello, Role, WtType, decode_nonce, decode_short, encode_hello

    async def nat_7500(enable):
        stop, task, _, tcp_port = await _start(tmp_path, enable_7500=enable)
        rd, wr = await asyncio.open_connection("127.0.0.1", tcp_port)
        n = decode_nonce(await rd.readexactly(20))
        wr.write(encode_hello(Hello(Role.NAT, 1, 7500, b"" * 8), SECRET.encode(), n))
        first = await asyncio.wait_for(rd.readexactly(4), 5)
        wr.close()
        stop.set()
        await asyncio.wait_for(task, 5)
        return first

    async def scenario():
        return await nat_7500(False), await nat_7500(True)

    off, on = asyncio.run(scenario())
    assert decode_short(off) == WtType.VERSION and on[:2] == b"WT" and on[3] == WtType.HELLO_OK
