**English** | [한국어](SECURITY.ko.md)

# Security

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on this repository. If that button isn't there, open an issue that says only "security contact needed" — no details — and you'll get a private channel.

You'll get a first answer within a week. Fixes go into a patch release, and the report is credited unless you'd rather not.

## Supported versions

The latest release only.

## What counts

Especially welcome:

- a way to make the reflector answer without the secret, answer more than once per sequence number, or answer with more bytes than it received;
- a way to read the dashboard or its API without the token, or to get around the Host check (DNS rebinding);
- anything in the public view, an alert, a bug report or a static export that reveals an address, a host name or other identifying data it shouldn't;
- the secret or the UI token showing up in a log, an export or an API response.

Known limits, documented in [design](docs/design.md#security), are not vulnerabilities: an attacker on the path can inject an RST and fake a NAT or IP-change verdict, and after a reflector crash packets from its last ≤ 10 s can be answered once.

## Hardening built in

- The secret comes from `WHYDROP_SECRET` only, must be ≥ 32 bytes, refuses the example value, and is never logged.
- The containers run as an unprivileged user with a read-only root, no capabilities and `no-new-privileges`.
- Release images are built in CI with an SBOM and provenance attestation; every GitHub Action is pinned to a commit.
