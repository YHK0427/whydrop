"""Test-only UDP relay that drops chosen WD seqs per direction (client→reflector = up, reflector→client = down)."""
import asyncio
import socket


def _seq(pkt: bytes) -> int | None:
    return int.from_bytes(pkt[8:12], "big") if len(pkt) == 44 else None


class _Side(asyncio.DatagramProtocol):
    def __init__(self, on_packet):
        self.on_packet = on_packet
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.on_packet(data, addr)

    def error_received(self, exc):
        pass


class LossProxy:
    def __init__(self, upstream: tuple[str, int], drop_up: set[int] = frozenset(), drop_down: set[int] = frozenset()):
        self.upstream = upstream
        self.drop_up, self.drop_down = set(drop_up), set(drop_down)
        self._client = None
        self.port = 0

    async def start(self) -> "LossProxy":
        loop = asyncio.get_running_loop()
        self._front, _ = await loop.create_datagram_endpoint(lambda: _Side(self._from_client),
                                                             local_addr=("127.0.0.1", 0), family=socket.AF_INET)
        self._back, _ = await loop.create_datagram_endpoint(lambda: _Side(self._from_reflector),
                                                            remote_addr=self.upstream, family=socket.AF_INET)
        self.port = self._front.get_extra_info("sockname")[1]
        return self

    def _from_client(self, data, addr):
        self._client = addr
        if _seq(data) not in self.drop_up:
            self._back.sendto(data)

    def _from_reflector(self, data, addr):
        if self._client and _seq(data) not in self.drop_down:
            self._front.sendto(data, self._client)

    def close(self):
        self._front.close()
        self._back.close()
