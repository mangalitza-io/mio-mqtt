import sys
from asyncio import (
    AbstractEventLoop,
    Future,
    StreamReader,
    StreamWriter,
    Task,
    get_running_loop,
)
from typing import Type

from mio_mqtt.packet.packet import Packet
from mio_mqtt.types import Address

from .mqtt_transport import MQTTTransport, ReceiverCallback
from .tcp_sock import TCPInet6Socket, TCPInetSocket, TcpSocket


class _MQTTStreamTransport(MQTTTransport):
    SOCKET_TYPE: Type[TcpSocket]

    def __init__(
        self, addr: Address, cb: ReceiverCallback, err_fut: Future[None]
    ) -> None:
        super().__init__(addr=addr, cb=cb, err_fut=err_fut)

        self._loop: AbstractEventLoop = None  # type: ignore[assignment]
        self._sock: TcpSocket = None  # type: ignore[assignment]
        self._s_reader: StreamReader = None  # type: ignore[assignment]
        self._s_writer: StreamWriter = None  # type: ignore[assignment]
        self._reader_loop_task: Task[None] = None  # type: ignore[assignment]

        self._read_tasks: set[Task[None]] = set()

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
            packet_body: bytearray
            if 0 < remaining_length:
                packet_body = bytearray(
                    await self._s_reader.readexactly(remaining_length)
                )
            else:
                packet_body = bytearray()
            packet: Packet = packet_type.from_bytes(
                fixed_byte=fixed_byte, packet_body=packet_body
            )
            task: Task[None] = self._loop.create_task(self._cb(packet))  # type: ignore[arg-type]
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

    async def send(self, packet: Packet) -> None:
        __data: bytes = packet.to_bytes()
        self._s_writer.write(__data)
        return await self._s_writer.drain()

    async def open(self) -> None:
        if self._loop is None:
            self._loop = get_running_loop()  # type: ignore[unreachable]
        self._sock = self.SOCKET_TYPE()
        (
            self._s_reader,
            self._s_writer,
        ) = await self._sock.create_stream_connection(
            address=self._addr, loop=self._loop
        )
        self._reader_loop_task = self._loop.create_task(self._read_loop())

    async def close(self) -> None:
        if self._s_writer is not None and not self._s_writer.is_closing():
            self._s_writer.close()
        if (
            self._reader_loop_task is not None
            and isinstance(self._reader_loop_task, Task) is True
        ):
            self._reader_loop_task.cancel()
        self._reset()

    def _reset(self) -> None:
        self._sock = None  # type: ignore[assignment]
        self._s_reader = None  # type: ignore[assignment]
        self._s_writer = None  # type: ignore[assignment]
        self._reader_loop_task = None  # type: ignore[assignment]


class MQTTInetStreamTransport(_MQTTStreamTransport):
    SOCKET_TYPE = TCPInetSocket


class MQTTInet6StreamTransport(_MQTTStreamTransport):
    SOCKET_TYPE = TCPInet6Socket


if sys.platform != "win32":

    class MQTTUnixStreamTransport(_MQTTStreamTransport):
        SOCKET_TYPE = TCPInet6Socket
