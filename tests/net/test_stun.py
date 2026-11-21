from whydrop.net.stun import build_binding, parse_binding_response

# RFC 5769 §2.2 sample IPv4 response (SOFTWARE, XOR-MAPPED-ADDRESS, MESSAGE-INTEGRITY, FINGERPRINT)
TXID = bytes.fromhex("b7e7a701bc34d686fa87dfae")
RFC5769_RESPONSE = bytes.fromhex(
    "0101003c2112a442b7e7a701bc34d686fa87dfae"
    "8022000b7465737420766563746f7220"
    "00200008 0001a147e112a643".replace(" ", "")
    + "000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7"
    + "80280004c07d4c96")


def test_binding_request_bytes():
    b = build_binding(TXID)
    assert b == bytes.fromhex("000100002112a442") + TXID and len(b) == 20


def test_stun_xor_mapped():
    assert parse_binding_response(RFC5769_RESPONSE, TXID) == ("192.0.2.1", 32853)


def test_stun_wrong_txid_none():
    assert parse_binding_response(RFC5769_RESPONSE, b"\x00" * 12) is None


def test_stun_garbage_none():
    assert parse_binding_response(b"\x01\x01\x00", TXID) is None
    assert parse_binding_response(RFC5769_RESPONSE[:30], TXID) is None


def test_mapped_address_fallback():
    body = bytes.fromhex("00010008") + bytes.fromhex("0001") + (40000).to_bytes(2, "big") + bytes([198, 51, 100, 7])
    msg = bytes.fromhex("0101") + len(body).to_bytes(2, "big") + bytes.fromhex("2112a442") + TXID + body
    assert parse_binding_response(msg, TXID) == ("198.51.100.7", 40000)
