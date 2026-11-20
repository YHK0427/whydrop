from whydrop.agent import env

RESOLV = """# generated
nameserver 192.168.0.1
nameserver 10.0.0.53
nameserver 100.100.100.100
nameserver 127.0.0.53
nameserver 198.51.100.53
search lan
"""


def test_isp_dns_exclusions():
    assert env.isp_dns_from(RESOLV, "192.168.0.1") == ("198.51.100.53",)


def test_isp_dns_excludes_gateway_even_if_public():
    assert env.isp_dns_from("nameserver 203.0.113.1\nnameserver 198.51.100.7\n", "203.0.113.1") == ("198.51.100.7",)


def test_isp_dns_excludes_cgnat_and_docker():
    assert env.isp_dns_from("nameserver 100.64.1.1\nnameserver 127.0.0.11\n", None) == ()


def test_vm_refusal():
    assert env.vm_refusal("5.15.153.1-microsoft-standard-WSL2", "172.20.0.1")
    assert env.vm_refusal("6.6.12-linuxkit", "192.168.65.1")
    assert env.vm_refusal("6.8.0-45-generic", "192.168.65.5")
    assert env.vm_refusal("6.8.0-45-generic", "192.168.0.1") is None
    assert "not yours" in env.vm_refusal("6.6.12-linuxkit", None)


def test_vpn_iface_names():
    assert env.is_vpn_iface("tailscale0") and env.is_vpn_iface("wg0") and env.is_vpn_iface("tun0")
    assert not env.is_vpn_iface("wlp1s0") and not env.is_vpn_iface(None)


def test_parse_ip_route_get():
    assert env.parse_ip_route_get("8.8.8.8 dev tailscale0 table 52 src 100.64.0.2 uid 1000\n    cache\n") == "tailscale0"
    assert env.parse_ip_route_get("8.8.8.8 via 192.168.0.1 dev wlp1s0 src 192.168.0.10 uid 1000\n") == "wlp1s0"
    assert env.parse_ip_route_get("") is None


def test_ipv6_default_route():
    line = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 wlan0\n"
    assert env.has_ipv6_default(line) and not env.has_ipv6_default("")


def test_chaos_site_verdict():
    assert env.chaos_verdict(["ICN"]) == "ok" and env.chaos_verdict(["dnsmasq-2.90"]) == "suspect"
    assert env.chaos_verdict([]) == "unknown"


def test_report_card_shape_and_privacy():
    from whydrop.agent.env import EnvInfo
    from whydrop.agent.report import google_verdict, report_card
    from whydrop.agent.selfcheck import SelfCheck
    sc = SelfCheck("ok", {"dns_public:1.1.1.1:53/tcp": "blocked on this network (tcp only)"}, {}, {"dns_public": 12.0})
    card = report_card(EnvInfo("wlan0", "192.0.2.1", "wifi", (), False, True), sc,
                       {"endpoint_independent": True, "port_preserving": False, "public_ip": "100.64.3.4"},
                       interception={"verdict": "ok"})
    assert card["protocol_blocks"] == ["dns_public:1.1.1.1:53/tcp"] and card["cgnat_hint"] is True
    assert card["nat_mapping"] == {"endpoint_independent": True, "port_preserving": False}
    assert "100.64.3.4" not in str(card) and card["ipv6_unmeasured"] is True
    assert google_verdict(["74.125.18.7"]) == "ok" and google_verdict(["198.51.100.9"]) == "suspect"
    assert google_verdict([]) == "unknown"
