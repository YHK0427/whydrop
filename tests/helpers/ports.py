"""A TCP and a UDP server on one port number, as the reflector and DNS servers have."""


async def tcp_then_udp(start_tcp, start_udp, tries: int = 20):
    """TCP first: Windows reserves blocks of TCP ports inside the UDP ephemeral range (Hyper-V), so the TCP twin of a
    UDP port can be refused (WSAEACCES) while the reverse rarely is. Returns (tcp_server, udp_result, port)."""
    for _ in range(tries):
        t = await start_tcp(0)
        port = t.sockets[0].getsockname()[1]
        try:
            return t, await start_udp(port), port
        except OSError:   # that UDP port is in use
            t.close()
    raise OSError("no port free for both TCP and UDP")
