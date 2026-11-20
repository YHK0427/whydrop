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
