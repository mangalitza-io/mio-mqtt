from asyncio import Event

from mio_mqtt.packet.packet import ConnAckPacket, ConnectPacket, PublishPacket
from mio_mqtt.packet.packet_parts import WillMessage
from mio_mqtt.types import DictStrObject


class Message(PublishPacket):
    def __init__(
        self,
        dup: bool,
        qos: int,
        retain: bool,
        topic: str = "",
        packet_id: int | None = None,
        properties: DictStrObject | None = None,
        payload: bytes | bytearray = b"",
    ) -> None:
        super(Message, self).__init__(
            dup=dup,
            qos=qos,
            retain=retain,
            topic=topic,
            packet_id=packet_id,
            properties=properties,
            payload=payload,
        )

        self._qos_1: Event = Event()
        self._qos_2: Event = Event()


class Connect(ConnectPacket):
    def __init__(
        self,
        client_id: str,
        clean_start: bool = True,
        username: str | None = None,
        password: str | None = None,
        keep_alive: int = 60,
        properties: DictStrObject | None = None,
        will_message: WillMessage | None = None,
    ) -> None:
        super(Connect, self).__init__(
            client_id=client_id,
            clean_start=clean_start,
            username=username,
            password=password,
            keep_alive=keep_alive,
            properties=properties,
            will_message=will_message,
        )
        self._conn_ack_waiter: Event = Event()
        self._conn_ack: ConnAckPacket = None  # type: ignore[assignment]
