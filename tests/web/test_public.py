import json
import re

from whydrop.web.public import mask_text, public

NOW = 1_800_000_100_000
SECRETS = ["192.168.0.1", "211.234.10.11", "203.0.113.7", "wlan0", "wlp3s0", "icn06", "home-server", "reflector.example.net",
           "100.107.1.2", ":48100", "40000", "40001"]   # mapped ports; well-known service ports (3478, 53) are fine

ROWS = {
    "incident": {"id": 3, "start_ms": NOW - 60_000, "end_ms": NOW - 14_000, "primary_cause": "R2", "cause_final": "R2",
                 "cause_changed": 0,
                 "tags_json": json.dumps({"tags": ["long_outage"], "segments": ["line"], "chain": [], "point": None,
                                          "iface": "wlan0"}),
                 "evidence_json": json.dumps({"label": "Line drop in the ISP segment (likely)", "cause": "R2",
                                              "next_step": "contact your ISP", "secondary": [],
                                              "protocol": "UDP: sent seq 1–9 to 203.0.113.7:48100; reflector.example.net",
                                              "events": ["stall"], "public_ip": "203.0.113.7"})},
    "event": [
        {"ts_ms": NOW - 5000, "kind": "ip_change", "pair": None, "detail_json": json.dumps({"old": "203.0.113.7", "new": "203.0.113.8"})},
        {"ts_ms": NOW - 5000, "kind": "net_change", "pair": None,
         "detail_json": json.dumps({"iface": "wlp3s0", "gateway_changed": True, "vpn": False})},
        {"ts_ms": NOW - 5000, "kind": "mapping_reset", "pair": "stun:stun.cloudflare.com:3478/udp",
         "detail_json": json.dumps({"old_port": 40000, "new_port": 40001, "ip": "203.0.113.7"})},
        {"ts_ms": NOW - 5000, "kind": "stall", "pair": "reflector", "detail_json": json.dumps({"phase": "end", "duration_s": 4.2})},
    ],
    "sample": [
        {"ts_ms": NOW - 3000, "probe": "dns", "pair": "dns_router:192.168.0.1:53/udp", "sent": 1, "ok": 1, "lost": 0},
        {"ts_ms": NOW - 3000, "probe": "dns", "pair": "dns_isp:211.234.10.11:53/udp", "sent": 1, "ok": 1, "lost": 0},
        {"ts_ms": NOW - 3000, "probe": "dns", "pair": "dns_public:8.8.8.8:53/udp", "sent": 1, "ok": 1, "lost": 0},
    ],
    "status": {"version": "0.1", "mode": "precision", "agent": "home-server", "reflector": "reflector.example.net:48100",
               "bytes": {"dns": 10}, "baseline": "learning", "now_ms": NOW},
    "selfcheck": {"ts_ms": NOW, "result_json": json.dumps({"excluded": {"dns_isp:211.234.10.11:53/tcp": "blocked"},
                                                           "chaos_site": "icn06", "gateway": "192.168.0.1"})},
}


def test_nothing_identifying_survives():
    out = json.dumps([public(ROWS["incident"], "incident", NOW), [public(e, "event", NOW) for e in ROWS["event"]],
                      [public(r, "sample", NOW) for r in ROWS["sample"]], public(ROWS["status"], "status", NOW),
                      public(ROWS["selfcheck"], "selfcheck", NOW)])
    for s in SECRETS:
        assert s not in out, s
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", out.replace("8.8.8.8", "")), "raw IPv4 left"


def test_internal_ips_keep_last_octet_public_resolvers_stay():
    rows = [public(r, "sample", NOW)["pair"] for r in ROWS["sample"]]
    assert rows == ["dns_router:x.x.x.1:53/udp", "dns_isp:hidden", "dns_public:8.8.8.8:53/udp"]


def test_times_become_relative():
    inc = public(ROWS["incident"], "incident", NOW)
    assert inc["start_s"] == -60 and inc["end_s"] == -14 and "start_ms" not in inc


def test_unknown_fields_dropped():
    assert public({"kind": "stall", "ts_ms": NOW, "pair": "reflector", "detail_json": "{}", "secret_thing": 1}, "event", NOW).keys() \
        == {"kind", "t_s", "pair", "detail"}


def test_event_details_by_allowlist():
    ev = [public(e, "event", NOW) for e in ROWS["event"]]
    assert ev[0]["detail"] == {} and ev[1]["detail"] == {"gateway_changed": True, "vpn": False}
    assert ev[3]["detail"] == {"phase": "end", "duration_s": 4.2}


def test_mask_text():
    t = mask_text("router 192.168.0.1, isp 211.234.10.11:53, me 203.0.113.7, dns 1.1.1.1, if wlan0, v6 2001:db8::1")
    assert t == "router x.x.x.1, isp hidden, me hidden, dns 1.1.1.1, if (interface), v6 hidden"



def test_line_hb_and_tcp_pairs_hide_reflector_and_unknown_hosts():
    from whydrop.web.public import mask_pair
    assert mask_pair("line_hb:203.0.113.50:48100/udp") == "line_hb:hidden"
    assert mask_pair("tcp:1.1.1.1:443/tcp") == "tcp:1.1.1.1:443/tcp"
    assert mask_pair("tcp:203.0.113.50:443/tcp") == "tcp:hidden:443/tcp"
    assert mask_pair("stun:reflector.example.net:3478/udp") == "stun:hidden:3478/udp"


def test_mask_text_leaves_clock_times_alone():
    assert mask_text("22:07:14 and 2001:db8::1 and fe80::1:2:3") == "22:07:14 and hidden and hidden"


def test_ipv6_after_a_colon_and_v6_pairs():
    from whydrop.web.public import mask_pair
    assert mask_text("peer:2001:db8::7") == "peer:hidden"
    assert mask_pair("tcp:2001:db8::7:443/tcp") == "tcp:hidden:443/tcp"
