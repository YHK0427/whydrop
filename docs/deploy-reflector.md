**English** | [한국어](deploy-reflector.ko.md)

# Deploying a reflector

The reflector is what turns on precision mode: upload/download separation, the TCP canaries and `nat-test`. It is a small whydrop process (standard library only) that answers authenticated packets on one port, 48100, over UDP and TCP.

## What you need

- A Linux machine **outside your home network** with a public IPv4 address: any VPS, or a free-tier VM from a cloud provider. Pick a region close to you; the round trip to it becomes the baseline of every precision measurement.
- Inbound UDP **and** TCP 48100 allowed, both in the provider's firewall (security group / security list) and on the machine itself.
- Docker, or Python 3.11–3.13.

One reflector and one secret can serve several agents.

## 1. Make a secret

On any machine:

```sh
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Keep it somewhere safe. It must be at least 32 bytes; the reflector and the agent both refuse the example value. The secret is never logged and never shown by the dashboard or the API.

## 2. Run the reflector

With Docker:

```sh
git clone https://github.com/YHK0427/whydrop && cd whydrop
docker build -t whydrop .
docker run -d --name whydrop-reflector --restart unless-stopped \
  -p 48100:48100/udp -p 48100:48100/tcp \
  -e WHYDROP_SECRET='paste-your-secret-here' \
  -v whydrop-reflector:/data --read-only --cap-drop ALL --security-opt no-new-privileges \
  whydrop reflector --state-dir /data
docker logs whydrop-reflector
```

You should see `whydrop reflector … listening udp :48100 tcp :48100`.

Without Docker (`pip install .` from a checkout, then):

```sh
WHYDROP_SECRET='paste-your-secret-here' whydrop reflector --state-dir /var/lib/whydrop-reflector
```

`--state-dir` holds the replay tombstones (the highest sequence number seen per session), which make captured packets worthless even after a restart. Keep it on persistent storage.

Options: `--port` (default 48100), `--host` (default 0.0.0.0), `--enable-7500` (allow the 7500 s TCP delay in `nat-test`; off by default because it keeps a connection open for two hours). The agent asks for that delay only with `whydrop nat-test --enable-7500` or `[nat] enable_7500 = true` in its `whydrop.toml`.

## 3. Open the port

In the provider's console, allow inbound **UDP 48100** and **TCP 48100** from anywhere (or only from your home's public IP, if it never changes). Then on the machine, if it runs a firewall:

```sh
sudo ufw allow 48100/udp && sudo ufw allow 48100/tcp          # Ubuntu with ufw
```

Some images ship with iptables rules that reject everything not explicitly allowed even when ufw is absent; check `sudo iptables -L INPUT -n` and add `ACCEPT` rules for both protocols ahead of the `REJECT` if needed.

## 4. Point the agent at it

In `.env` next to the agent's `compose.yaml`:

```sh
WHYDROP_REFLECTOR=your.reflector.address      # host or host:port
WHYDROP_SECRET=paste-your-secret-here
```

Then `docker compose up -d`. On the dashboard's Now page the TCP lane starts showing the hot connection. If precision mode can't turn on, `docker compose logs whydrop` says why (`precision mode off: WHYDROP_SECRET not set`, …); if the reflector rejects the secret, the dashboard shows a banner saying so. Run `docker compose exec whydrop whydrop nat-test` to try the whole path once.

## Is it safe to run?

- Without the secret, the reflector answers nothing: every UDP packet must carry a valid HMAC, and every TCP connection must answer a nonce challenge first.
- It cannot be used to amplify traffic: a reply is never larger than the request, and a NAT test request gets at most two replies.
- Junk is dropped before any hashing (wrong size, magic or type), and each source IP is rate limited before and after the HMAC check.
- Every sequence number is answered once; replayed packets get nothing.
- It keeps no logs of payloads; it logs a per-minute count of dropped packets by reason.

Details in [design § Security](design.md#security), and the wire format in [protocol](protocol.md).

## Costs

The traffic of one agent in precision mode is about 18.5 kbit/s in both directions together, which is around 6 GB a month — inside every free tier we know of, but check your provider's egress allowance.
