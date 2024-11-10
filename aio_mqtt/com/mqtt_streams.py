from asyncio import (
    AbstractEventLoop,
    StreamReader,
    StreamWriter,
    Task,
    get_running_loop,
)
from collections.abc import Callable
from typing import Awaitable, Type, TypeAlias

from aio_mqtt.packet.packet import (
    AuthPacket,
    ConnAckPacket,
    ConnectPacket,
    DisconnectPacket,
    Packet,
    PingReqPacket,
    PingRespPacket,
    PubAckPacket,
    PubCompPacket,
    PublishPacket,
    PubRecPacket,
    PubRelPacket,
    SubAckPacket,
    SubscribePacket,
    UnSubAckPacket,
    UnSubscribePacket,
)
from aio_mqtt.types import Address

from .tcp_sock import TcpSocket

_ReceiverCallback: TypeAlias = Callable[[Packet], Awaitable[None]]
_PacketTypeMap: TypeAlias = dict[int, Type[Packet]]


class _MqttStreamClient:
    def __init__(
        self, addr: Address, cb: _ReceiverCallback, sock_type: Type[TcpSocket]
    ) -> None:
        self._addr: Address = addr
        self._cb: _ReceiverCallback = cb
        self._sock_type: Type[TcpSocket] = sock_type

        self._loop: AbstractEventLoop = None  # type: ignore[assignment]
        self._sock: TcpSocket = None  # type: ignore[assignment]
        self._s_reader: StreamReader = None  # type: ignore[assignment]
        self._s_writer: StreamWriter = None  # type: ignore[assignment]
        self._reader_loop_task: Task[None] = None  # type: ignore[assignment]

        self._packet_type_map: _PacketTypeMap = {
            packet.TYPE: packet  # type: ignore[type-abstract]
            for packet in Packet.__subclasses__()
        }
        self._read_tasks: set[Task[None]] = set()

    async def _read_loop(self) -> None:
        while True:
            fixed_byte: int = (await self._s_reader.readexactly(1))[0]
            print(f"{self._read_loop.__qualname__}: Read {fixed_byte}")
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
        self._sock = self._sock_type()
        (
            self._s_reader,
            self._s_writer,
        ) = await self._sock.create_stream_connection(
            address=self._addr, loop=self._loop
        )
        self._reader_loop_task = self._loop.create_task(self._read_loop())

    async def close(self) -> None:
        self._s_writer.close()
        self._reader_loop_task.cancel()

    def _reset(self) -> None:
        self._sock = None  # type: ignore[assignment]
        self._s_reader = None  # type: ignore[assignment]
        self._s_writer = None  # type: ignore[assignment]
        self._reader_loop_task = None  # type: ignore[assignment]


class MqttStreamClient:
    def __init__(self, addr: Address, sock_type: Type[TcpSocket]) -> None:
        self._addr: Address = addr
        self._sock_type: Type[TcpSocket] = sock_type

        self._is_open: bool = False

        self._msc: _MqttStreamClient = _MqttStreamClient(
            addr=addr,
            cb=self._handle_inc_packets,
            sock_type=sock_type,
        )

    async def _handle_inc_packets(self, packet: Packet) -> None:
        print(f"{self._handle_inc_packets.__qualname__}.{packet = }")

    async def send_connect(self, packet: ConnectPacket) -> None:
        if self._is_open is False:
            await self._msc.open()
        return await self._msc.send(packet)

    async def send_publish(self, packet: PublishPacket) -> None:
        return await self._msc.send(packet)

    async def send_puback(self, packet: PubAckPacket) -> None:
        return await self._msc.send(packet)

    async def send_pubrec(self, packet: PubRecPacket) -> None:
        return await self._msc.send(packet)

    async def send_pubrel(self, packet: PubRelPacket) -> None:
        return await self._msc.send(packet)

    async def send_pubcomp(self, packet: PubCompPacket) -> None:
        return await self._msc.send(packet)

    async def send_subscribe(self, packet: SubscribePacket) -> None:
        return await self._msc.send(packet)

    async def send_unsubscribe(self, packet: UnSubscribePacket) -> None:
        return await self._msc.send(packet)

    async def send_pingreq(self, packet: PingReqPacket) -> None:
        return await self._msc.send(packet)

    async def send_disconnect(self, packet: DisconnectPacket) -> None:
        return await self._msc.send(packet)

    async def send_auth(self, packet: AuthPacket) -> None:
        return await self._msc.send(packet)
