"""A recorded-looking DB with every dashboard state, plus a preview server: `python tests/ui/fixture.py [port]`.
Uses documentation-range addresses only."""
import asyncio
import json
import math
import random
import sys
import time
from pathlib import Path

from whydrop.agent.events import Event
from whydrop.agent.store import SampleRow, Store

MODES = ("precision", "basic")


def build(path: Path, mode: str = "precision", now_ms: int | None = None, outage_open: bool = False) -> dict:
    now = (now_ms or int(time.time() * 1000)) // 1000 * 1000
    rnd = random.Random(4)
    drop_a, drop_b = now - 40 * 60_000, now - 46_000 * 0 - 3 * 3600_000

    async def go():
        s = Store(path)
        await s.open()
        run = await s.run_start(now - 26 * 3600_000, "0.1.0", {"mode": mode})
        await s.run_heartbeat(run, now)
        rows = []
        for sec in range(0, 2 * 3600):
            t = now - 2 * 3600_000 + sec * 1000
            down = drop_a <= t < drop_a + 46_000
            base = 18 + 4 * math.sin(sec / 300) + rnd.random() * 2
            for i, prov in enumerate(("cloudflare", "google", "quad9")):
                if sec % 3 == i:
                    rows.append(SampleRow(t, "line_hb", f"line_hb:{prov}", 1, 0 if down else 1, 1 if down else 0,
                                          rtt_avg=None if down else round(base + i, 1)))
            rows.append(SampleRow(t, "gateway", "gateway", 1, 1, 0, rtt_avg=2.1))
            if mode == "precision":
                lost = 10 if down else (1 if rnd.random() < 0.02 else 0)
                rows.append(SampleRow(t, "udp_stream", "reflector", 10, 10 - lost, lost, lost_up=lost if down else 0,
                                      lost_down=0 if down else lost, rtt_avg=None if lost == 10 else round(base + 6, 1)))
                rows.append(SampleRow(t, "canary", "reflector", 1, 0 if down else 1, 1 if down else 0,
                                      rtt_avg=None if down else round(base + 6, 1)))
        await s.add_samples(rows)
        await s.add_events([Event("stall", drop_a + 3000, "reflector", {"phase": "start", "canary": "hot"}),
                            Event("stall", drop_a + 47_000, "reflector", {"phase": "end", "duration_s": 44.0, "canary": "hot"}),
                            Event("roam", now - 90 * 60_000, None, {"from": "AP 1", "to": "AP 2"})])
        await s.flush()
        ev = {"label": "Line drop in the ISP segment (likely)", "cause": "R2",
              "next_step": "Save the evidence with export and contact your ISP", "secondary": [],
              "protocol": "UDP: sent seq 1201–1660; reflector recv_count +0 → all lost upstream. TCP: HB got no reply; "
                          "the kernel retransmitted 5 times (RTO 0.2 → 3.2 s); no RST, so the connection survived; "
                          "the first HB_ACK came after 44.0 s of silence.",
              "protocol_ko": "UDP: seq 1201–1660 전송, reflector의 recv_count +0 → 모두 올라가는 길에서 사라졌어요. "
                             "TCP: HB에 응답이 없었어요. 커널이 5번 재전송했어요(RTO 0.2 → 3.2초). "
                             "RST가 없어 연결은 살아 있었어요. 44.0초 동안 조용하다가 첫 HB_ACK이 왔어요.",
              "cause_direction": "upload", "events": ["stall", "tcp_info", "udp_outage"]}
        await s.insert("incidents", start_ms=drop_a, end_ms=drop_a + 46_000, primary_cause="R2", cause_final="R2", cause_changed=0,
                       tags_json=json.dumps({"tags": [], "segments": ["line"], "chain": [], "point": None}),
                       evidence_json=json.dumps(ev))
        await s.insert("incidents", start_ms=drop_b, end_ms=drop_b + 20_000, primary_cause="R3", cause_final="R3", cause_changed=1,
                       tags_json=json.dumps({"tags": [], "segments": ["dns_router"], "chain": [], "point": None}),
                       evidence_json=json.dumps({"label": "Router DNS failure (likely)", "cause": "R3", "provisional": "R2",
                                                 "next_step": "Switch your device or router to a public DNS"}))
        if outage_open:
            await s.insert("incidents", start_ms=now - 32_000, end_ms=None, primary_cause="R2",
                           tags_json=json.dumps({"tags": [], "segments": ["line"], "chain": [], "point": None}),
                           evidence_json=json.dumps({"label": "Line drop in the ISP segment (likely)", "cause": "R2"}))
        await s.insert("conditions", kind="loss", start_ms=now - 20 * 60_000, end_ms=None,
                       detail_json=json.dumps({"loss": 0.07, "cause": "R6", "label": "Lossy line (likely)"}))
        await s.insert("annotations", start_ms=drop_a - 5000, end_ms=drop_a + 60_000, label="reproduced", note="router test")
        run_id = await s.insert("nat_runs", start_ms=now - 3600_000, end_ms=now - 3000_000, status="done",
                                detail_json=json.dumps({"udp_range": [30, 45], "tcp_range": [600, 1200]}))
        for proto, delay, alive in (("udp", 10, 1), ("udp", 20, 1), ("udp", 30, 1), ("udp", 45, 0), ("udp", 60, 0),
                                    ("tcp", 60, 1), ("tcp", 300, 1), ("tcp", 600, 1), ("tcp", 1200, 0), ("tcp", 1800, None)):
            await s.insert("nat_results", run_id=run_id, proto=proto, delay_s=delay, alive=alive, detail_json="{}")
        if mode == "precision":
            ring = [(drop_a - 5000 + i * 100, 1150 + i, i < 50 or i > 510, "ok" if (i < 50 or i > 510) else "up")
                    for i in range(600)]
            await s.executemany("INSERT INTO udp_seq_ring (agent_id, ts_ms, seq, echoed, dir) VALUES (1, ?, ?, ?, ?)",
                                [(a, b, int(c), d) for a, b, c, d in ring])
        await s.insert("selfcheck", ts_ms=now - 26 * 3600_000, result_json=json.dumps(
            {"verdict": "ok", "excluded": {"dns_public:1.1.1.1:53/udp": "no answer on this network",
                                           "dns_isp:x.x.x.53:53/tcp": "blocked on this network (tcp only)"}}))
        await s.close()
    asyncio.run(go())
    segs = {"host_net": "up", "wifi": "up", "link": "unknown", "lan": "up", "line": "down" if outage_open else "up", "dns": "up"}
    return {"version": "0.1.0", "mode": mode, "agent": "home", "baseline": "ready", "now_ms": now, "segments": segs,
            "signal_dbm": -57, "link": "wifi", "vpn": False, "since_ms": now - 26 * 3600_000, "bytes": {}}


def serve(port: int = 8799, mode: str = "precision", outage_open: bool = False):
    import tempfile

    import uvicorn

    from whydrop.web.app import create_app
    from whydrop.web.bus import Bus
    db = Path(tempfile.mkdtemp()) / "w.db"
    st = build(db, mode, outage_open=outage_open)
    app = create_app(db, Bus(), token=None, allowed_hosts=["127.0.0.1", "localhost"], public_default=False,
                     status=lambda: {**st, "now_ms": int(time.time() * 1000)}, nat_run=lambda: True)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8799, sys.argv[2] if len(sys.argv) > 2 else "precision",
          len(sys.argv) > 3 and sys.argv[3] == "open")
