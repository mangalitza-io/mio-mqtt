import sys
from asyncio import (
    AbstractEventLoop,
    Event,
    Future,
    TimeoutError,
    get_running_loop,
    sleep,
    wait_for,
)
from time import monotonic_ns
from typing import Type

from mio_mqtt.com.mqtt_streams import (
    MQTTInet6StreamTransport,
    MQTTInetStreamTransport,
)

if sys.platform != "win32":
    from mio_mqtt.com.mqtt_streams import MQTTUnixStreamTransport
from mio_mqtt.com.mqtt_transport import MQTTTransport, ReceiverCallback
from mio_mqtt.enhanced_packets import Connect, Message
from mio_mqtt.packet.packet import (
    AuthPacket,
    ConnAckPacket,
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
    UnSubAckPacket,
)
from mio_mqtt.packet.reason_codes import SUCCESS
from mio_mqtt.types import Address


class _BaseClient:
    KEEPALIVE_SLEEP_FACTOR: float = 0.5
    KEEPALIVE_TIMEOUT_FACTOR: float = 0.5

    def __init__(
        self, addr: Address, transport_type: Type[MQTTTransport]
    ) -> None:
        self._addr: Address = addr
        self._transport_type: Type[MQTTTransport] = transport_type

        self._keep_alive_time = 60
        self._last_message_time: float = 0
        self._keep_alive_waiter: Event = Event()

        self._loop: AbstractEventLoop = None  # type: ignore[assignment]
        self._transport: MQTTTransport = None  # type: ignore[assignment]
        self._connection_err: Future[None] = None  # type: ignore[assignment]
        self._connect: Connect = None  # type: ignore[assignment]

        self._recv_handlers: dict[int, ReceiverCallback] = {
            ConnAckPacket.TYPE: self._handle_connack,  # type: ignore[dict-item]
            PublishPacket.TYPE: self._handle_publish,  # type: ignore[dict-item]
            PubAckPacket.TYPE: self._handle_puback,  # type: ignore[dict-item]
            PubRecPacket.TYPE: self._handle_pubrec,  # type: ignore[dict-item]
            PubRelPacket.TYPE: self._handle_pubrel,  # type: ignore[dict-item]
            PubCompPacket.TYPE: self._handle_pubcomp,  # type: ignore[dict-item]
            SubAckPacket.TYPE: self._handle_suback,  # type: ignore[dict-item]
            UnSubAckPacket.TYPE: self._handle_unsuback,  # type: ignore[dict-item]
            PingRespPacket.TYPE: self._handle_pingresp,  # type: ignore[dict-item]
            DisconnectPacket.TYPE: self._handle_disconnect,  # type: ignore[dict-item]
            AuthPacket.TYPE: self._handle_auth,  # type: ignore[dict-item]
        }
        self._outgoing_packets: dict[int, Packet] = {}
        self._incoming_messages: dict[int, Message] = {}

    async def _handle_connack(self, packet: ConnAckPacket) -> None:
        if self._connect is not None:
            raise RuntimeError()
        self._connect._conn_ack = packet  # type: ignore[unreachable]
        self._connect._conn_ack_waiter.set()

    async def _handle_publish(self, packet: PublishPacket) -> None:
        # from server
        match packet._qos:
            case 0:
                # TODO pass over the Message
                ...
            case 1:
                # TODO extend
                if packet._packet_id is None:
                    raise RuntimeError()
                pub_ack: PubAckPacket = PubAckPacket(
                    packet_id=packet._packet_id, reason_code=SUCCESS
                )
                await self._send_packet(pub_ack)
                # TODO pass over the Message
            case 2:
                # TODO extend
                if packet._packet_id is None:
                    raise RuntimeError()
                pub_rec: PubRecPacket = PubRecPacket(
                    packet_id=packet._packet_id, reason_code=SUCCESS
                )
                await self._send_packet(pub_rec)

            case _:
                raise RuntimeError()

    async def _handle_puback(self, packet: PubAckPacket) -> None:
        # TODO Qos 1 message was successful sent
        ...

    async def _handle_pubrec(self, packet: PubRecPacket) -> None:
        # TODO Qos 2 message sent part 1
        # TODO extend
        pub_rel: PubRelPacket = PubRelPacket(
            packet_id=packet._packet_id, reason_code=SUCCESS
        )
        await self._send_packet(pub_rel)

    async def _handle_pubrel(self, packet: PubRelPacket) -> None:
        # TODO Qos 2 message received part 1
        # TODO extend
        pub_comp: PubCompPacket = PubCompPacket(
            packet_id=packet._packet_id, reason_code=SUCCESS
        )
        await self._send_packet(pub_comp)

    async def _handle_pubcomp(self, packet: PubCompPacket) -> None:
        # TODO Qos 2 message sent part 2
        # TODO pass over the Message
        ...

    async def _handle_suback(self, packet: SubAckPacket) -> None: ...

    async def _handle_unsuback(self, packet: UnSubAckPacket) -> None: ...

    async def _handle_pingresp(self, packet: PingRespPacket) -> None:
        self._keep_alive_waiter.set()

    async def _handle_disconnect(self, packet: DisconnectPacket) -> None: ...

    async def _handle_auth(self, packet: AuthPacket) -> None: ...

    async def _on_packet(self, packet: Packet) -> None:
        try:
            recv_callback = self._recv_handlers[packet.TYPE]
        except KeyError:
            return None
        return await recv_callback(packet)

    async def _ping_keep_alive(self) -> None:
        if not (0 < self.KEEPALIVE_SLEEP_FACTOR <= 1.0):
            raise ValueError()
        if not (0 < self.KEEPALIVE_TIMEOUT_FACTOR <= 1.0):
            raise ValueError()

        interval_ns: float = self._keep_alive_time * 1_000_000_000
        sleep_time: float = self._keep_alive_time * self.KEEPALIVE_SLEEP_FACTOR
        timeout: float = self._keep_alive_time * self.KEEPALIVE_TIMEOUT_FACTOR

        ping_req_packet: PingReqPacket = PingReqPacket()
        while True:
            curr_time_ns: float = monotonic_ns()
            if interval_ns <= curr_time_ns - self._last_message_time:
                await self._send_packet(ping_req_packet)
                try:
                    await wait_for(
                        fut=self._keep_alive_waiter.wait(), timeout=timeout
                    )
                except TimeoutError:
                    # TODO fix this, for reconnect
                    await self.close()
                    return None
                else:
                    self._keep_alive_waiter.clear()

            await sleep(sleep_time)

    async def _send_packet(self, packet: Packet) -> None:
        self._last_message_time = monotonic_ns()
        return await self._transport.send(packet)

    def _reset(self) -> None:
        self._connection_err = None  # type: ignore[assignment]
        self._transport = None  # type: ignore[assignment]

    async def _reconnect(self) -> None: ...

    async def connect(self) -> None:
        if self._loop is None:
            self._loop = get_running_loop()  # type: ignore[unreachable]
        if self._connection_err is None:
            self._connection_err = self._loop.create_future()  # type: ignore[unreachable]
        if self._transport is None:
            self._transport = self._transport_type(  # type: ignore[unreachable]
                addr=self._addr,
                cb=self._on_packet,
                err_fut=self._connection_err,
            )
        await self._transport.open()

    async def close(self) -> None:
        if (
            isinstance(self._connection_err, Future) is True
            and not self._connection_err.cancelled()
        ):
            self._connection_err.cancel()
        if isinstance(self._transport, MQTTTransport) is True:
            await self._transport.close()


class MQTTv5Client(_BaseClient):
    def __init__(
        self, addr: Address, transport_type: Type[MQTTTransport]
    ) -> None:
        super().__init__(addr=addr, transport_type=transport_type)

    @classmethod
    def with_tcp(cls, addr: Address) -> "MQTTv5Client":
        if isinstance(addr, tuple):
            try:
                host, port = addr
            except ValueError:
                pass
            else:
                if not isinstance(host, str):
                    raise TypeError()
                if not isinstance(port, int):
                    raise TypeError()
                return cls.with_inet(
                    host=host,
                    port=port,
                )
            try:
                host, port, flow_info, scope_id = addr
            except ValueError:
                pass
            else:
                if not isinstance(host, str):
                    raise TypeError()
                if not isinstance(port, int):
                    raise TypeError()
                if not isinstance(flow_info, int):
                    raise TypeError()
                if not isinstance(scope_id, int):
                    raise TypeError()
                return cls.with_inet6(
                    host=host,
                    port=port,
                    flow_info=flow_info,
                    scope_id=scope_id,
                )
        elif isinstance(addr, str) and sys.platform != "win32":
            return cls.with_unix(
                addr=addr,
            )

        raise TypeError()

    @classmethod
    def with_inet(cls, host: str, port: int) -> "MQTTv5Client":
        addr: Address = (host, port)
        return cls(
            addr=addr,
            transport_type=MQTTInetStreamTransport,
        )

    @classmethod
    def with_inet6(
        cls,
        host: str,
        port: int,
        flow_info: int,
        scope_id: int,
    ) -> "MQTTv5Client":
        addr: Address = (host, port, flow_info, scope_id)
        return cls(
            addr=addr,
            transport_type=MQTTInet6StreamTransport,
        )

    if sys.platform != "win32":

        @classmethod
        def with_unix(cls, addr: str) -> "MQTTv5Client":
            return cls(
                addr=addr,
                transport_type=MQTTUnixStreamTransport,
            )
