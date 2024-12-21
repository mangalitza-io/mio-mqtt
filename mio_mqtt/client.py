import sys
from asyncio import (
    AbstractEventLoop,
    Event,
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
from mio_mqtt.packet import WillMessage

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
from mio_mqtt.types import Address, DictStrObject


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
        self._connect_packet: Connect = None  # type: ignore[assignment]

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
        if self._connect_packet is None:
            raise RuntimeError()
        self._connect_packet._conn_ack = packet
        self._connect_packet._conn_ack_waiter.set()

    async def _handle_publish(self, packet: PublishPacket) -> None:
        # from server
        match packet._qos:
            case 0:
                # TODO pass over the Message
                # Received QoS 0 PublishPacket
                ...
            case 1:
                # TODO extend
                # Received QoS 1 PublishPacket
                if packet._packet_id is None:
                    raise RuntimeError()
                pub_ack: PubAckPacket = PubAckPacket(
                    packet_id=packet._packet_id, reason_code=SUCCESS
                )
                await self._send_packet(pub_ack)
                # TODO pass over the Message
            case 2:
                # TODO extend
                # Received QoS 2 PublishPacket
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
        # Received QoS 1 PubAckPacket, so sent Qos 1 Publish packet is acked
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
        print(f"{self._on_packet.__qualname__}.{packet = }")
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
                    await self._close()
                    return None
                else:
                    self._keep_alive_waiter.clear()

            await sleep(sleep_time)

    async def _send_packet(self, packet: Packet) -> None:
        self._last_message_time = monotonic_ns()
        return await self._transport.send(packet)

    def _reset(self) -> None:
        self._transport = None  # type: ignore[assignment]

    async def _reconnect(self) -> None: ...

    async def _connect(self) -> None:
        if self._loop is None:
            self._loop = get_running_loop()  # type: ignore[unreachable]
        if self._transport is None:
            self._transport = self._transport_type(  # type: ignore[unreachable]
                addr=self._addr,
                cb=self._on_packet,
            )
        await self._transport.open()

    async def _close(self) -> None:
        if isinstance(self._transport, MQTTTransport) is True:
            await self._transport.close()


class MQTTv5Client(_BaseClient):
    def __init__(
        self, addr: Address, transport_type: Type[MQTTTransport]
    ) -> None:
        super().__init__(addr=addr, transport_type=transport_type)

    @classmethod
    def with_inet(cls, addr: Address) -> "MQTTv5Client":
        return cls(
            addr=addr,
            transport_type=MQTTInetStreamTransport,
        )

    @classmethod
    def with_inet6(cls, addr: Address) -> "MQTTv5Client":
        return cls(
            addr=addr,
            transport_type=MQTTInet6StreamTransport,
        )

    @classmethod
    def with_unix(cls, addr: Address) -> "MQTTv5Client":
        if sys.platform == "win32":
            raise NotImplementedError()
        return cls(  # type:ignore[unreachable,unused-ignore]
            addr=addr,
            transport_type=MQTTUnixStreamTransport,  # type:ignore[name-defined,unused-ignore]
        )

    async def connect(
        self,
        client_id: str,
        clean_start: bool = True,
        username: str | None = None,
        password: str | None = None,
        keep_alive: int = 60,
        properties: DictStrObject | None = None,
        will_message: WillMessage | None = None,
    ) -> None:
        self._connect_packet = Connect(
            client_id=client_id,
            clean_start=clean_start,
            username=username,
            password=password,
            keep_alive=keep_alive,
            properties=properties,
            will_message=will_message,
        )
        await self._connect()
        await self._send_packet(packet=self._connect_packet)
        await self._connect_packet._conn_ack_waiter.wait()

    async def disconnect(self) -> None: ...
    async def publish(self) -> None: ...
    async def subscribe(self) -> None: ...
    async def unsubscribe(self) -> None: ...
