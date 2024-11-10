from asyncio import AbstractEventLoop, Protocol, StreamReader, StreamWriter
from collections.abc import Callable
from typing import TypeAlias

ProtocolFactory: TypeAlias = Callable[[], Protocol]


class MqttStreamClient:
    def __init__(self) -> None:
        self._is_open: bool = False

        self._loop: AbstractEventLoop = None  # type: ignore[assignment]
        self._s_reader: StreamReader = None  # type: ignore[assignment]
        self._s_writer: StreamWriter = None  # type: ignore[assignment]

    async def _read_length(self) -> int:
        multiplier: int = 1
        value: int = 0
        while True:
            encoded_byte: bytes = await self._s_reader.read(1)
            if 0 == len(encoded_byte):
                raise ValueError()
            encoded_int: int = int.from_bytes(encoded_byte, "big")
            value += (encoded_int & 0x7F) * multiplier
            if multiplier > 0x200000:
                raise ValueError()
            if (encoded_int & 0x80) == 0:
                break
            multiplier *= 0x80

        return value

    async def _read_loop(self) -> None:
        while True:
            fixed_header: int = (await self._s_reader.read(1))[0]

            packet_type = (fixed_header >> 4) & 0x0F

    async def send_connect(self) -> None:
        if self._is_open is False:
            await self.open()

    async def send_publish(self) -> None:
        ...

    async def send_puback(self) -> None:
        ...

    async def send_pubrec(self) -> None:
        ...

    async def send_pubrel(self) -> None:
        ...

    async def send_pubcomp(self) -> None:
        ...

    async def send_subscribe(self) -> None:
        ...

    async def send_unsubscribe(self) -> None:
        ...

    async def send_pingreq(self) -> None:
        ...

    async def send_disconnect(self) -> None:
        ...

    async def send_auth(self) -> None:
        ...

    async def open(self) -> None:
        ...

    async def close(self) -> None:
        ...
