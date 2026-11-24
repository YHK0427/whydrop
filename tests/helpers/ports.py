"""A TCP and a UDP server on one port number, as the reflector and DNS servers have."""
import random


async def tcp_then_udp(start_tcp, start_udp, tries: int = 100):
    """Windows (Hyper-V) reserves blocks of 100 TCP and UDP ports inside the dynamic range, and moves them; ephemeral
    ports are handed out in order, so retrying port 0 can walk one block for a long time. Random numbers below the
    dynamic range (49152) avoid that. Returns (tcp_server, udp_result, port)."""
    rng = random.Random()
    for _ in range(tries):
        port = rng.randint(20000, 45000)
        try:
            t = await start_tcp(port)
        except OSError:   # in use or reserved
            continue
        try:
            return t, await start_udp(port), port
        except OSError:
            t.close()
    raise OSError("no port free for both TCP and UDP")
