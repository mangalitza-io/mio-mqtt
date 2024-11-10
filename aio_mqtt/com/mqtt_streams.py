from asyncio import (
    AbstractEventLoop,
    Protocol,
    StreamReader,
    StreamWriter,
    Task,
)
from collections.abc import Callable
from time import monotonic
from typing import Awaitable, Type, TypeAlias

from aio_mqtt.packet.packet import Packet

_ReceiverCallback: TypeAlias = Callable[[Packet], Awaitable[None]]
_PacketTypeMap: TypeAlias = dict[int, Type[Packet]]


class MqttStreamClient:
    def __init__(self) -> None:
        self._is_open: bool = False

        self._loop: AbstractEventLoop = None  # type: ignore[assignment]
        self._s_reader: StreamReader = None  # type: ignore[assignment]
        self._s_writer: StreamWriter = None  # type: ignore[assignment]

        self._packet_type_map: _PacketTypeMap = {
            packet.TYPE: packet for packet in Packet.__subclasses__()
            # type: ignore[type-abstract]
        }
        self._read_tasks: set[Task[None]] = set()

        self._reader_loop_task: Task[None]

    async def _read_loop(self) -> None:
        while True:
            fixed_byte: int = (await self._s_reader.readexactly(1))[0]
            packet_type_val: int = (fixed_byte >> 4) & 0x0F
            try:
                packet_type: Type[Packet] = self._packet_type_map[
                    packet_type_val
                ]
            except KeyError:
                raise OSError()

            remaining_length: int = await self._decode_remaining_length()
            packet_body: bytes
            if 0 < remaining_length:
                packet_body = await self._s_reader.readexactly(
                    remaining_length
                )
            else:
                packet_body = b""
            packet: Packet = packet_type.from_bytes(
                fixed_byte=fixed_byte, packet_body=packet_body
            )
            task: Task[None] = self._loop.create_task(
                self._handle_inc_packets(packet)
            )
            self._read_tasks.add(task)

    async def _decode_remaining_length(self) -> int:
        multiplier: int = 1
        value: int = 0
        while True:
            try:
                encoded_byte: int = (await self._s_reader.readexactly(1))[0]
            except IndexError:
                raise ValueError()
            value += (encoded_byte & 0x7F) * multiplier
            if multiplier > 0x200000:
                raise ValueError()
            if (encoded_byte & 0x80) == 0:
                break
            multiplier *= 0x80

        return value

    async def _handle_inc_packets(self, packet: Packet) -> None:
        print(f"{self._handle_inc_packets.__name__}.{packet = }")

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
