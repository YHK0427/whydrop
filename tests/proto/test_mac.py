import hmac

import pytest

from whydrop.proto.mac import EXAMPLE_SECRET, MAC_LEN, SecretError, hmac8, load_secret


def test_hmac8_known_vector():
    assert hmac8(b"k" * 32, b"abc") == hmac.new(b"k" * 32, b"abc", "sha256").digest()[:8]
    assert MAC_LEN == 8


def test_secret_missing_optional():
    assert load_secret({}, required=False) is None


def test_secret_missing_required():
    with pytest.raises(SecretError, match="WHYDROP_SECRET"):
        load_secret({}, required=True)


def test_secret_too_short():
    with pytest.raises(SecretError, match="32"):
        load_secret({"WHYDROP_SECRET": "x" * 31}, required=True)


def test_secret_example_refused():
    with pytest.raises(SecretError, match="example"):
        load_secret({"WHYDROP_SECRET": EXAMPLE_SECRET}, required=True)


def test_secret_ok():
    assert load_secret({"WHYDROP_SECRET": "a" * 32}, required=True) == b"a" * 32


def test_secret_never_in_message():
    with pytest.raises(SecretError) as e:
        load_secret({"WHYDROP_SECRET": "short-secret"}, required=True)
    assert "short-secret" not in str(e.value)
