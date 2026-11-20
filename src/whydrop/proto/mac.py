"""Truncated HMAC used by every whydrop message, and the shared-secret policy."""
import hashlib
import hmac
from collections.abc import Mapping

MAC_LEN = 8
MIN_SECRET_BYTES = 32
EXAMPLE_SECRET = "REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES"
ENV_NAME = "WHYDROP_SECRET"


class SecretError(ValueError):
    """The shared secret is missing or unusable. Messages never contain the secret."""


def hmac8(secret: bytes, data: bytes) -> bytes:
    return hmac.new(secret, data, hashlib.sha256).digest()[:MAC_LEN]


def load_secret(env: Mapping[str, str], *, required: bool) -> bytes | None:
    value = env.get(ENV_NAME)
    if not value:
        if required:
            raise SecretError(f"{ENV_NAME} is not set; generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\"")
        return None
    if "REPLACE_WITH" in value:
        raise SecretError(f"{ENV_NAME} is still the example value; generate a real one")
    secret = value.encode("utf-8")
    if len(secret) < MIN_SECRET_BYTES:
        raise SecretError(f"{ENV_NAME} must be at least {MIN_SECRET_BYTES} bytes (got {len(secret)})")
    return secret
