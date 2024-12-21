from asyncio import Event

from mio_mqtt.packet import EncodeError
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

    @property
    def dup(self) -> bool:
        return self._dup

    @property
    def qos(self) -> int:
        return self._qos

    @property
    def retain(self) -> bool:
        return self._retain

    @property
    def topic(self) -> str:
        return self._topic

    @property
    def packet_id(self) -> int | None:
        return self._packet_id

    @property
    def properties(self) -> DictStrObject:
        return self._properties

    @property
    def payload(self) -> bytes | bytearray:
        return self._payload

    def get_property(self, __key: str) -> object:
        return self._properties[__key]


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

    @classmethod
    def with_validation(
        cls,
        client_id: str,
        clean_start: bool = True,
        username: str | None = None,
        password: str | None = None,
        keep_alive: int = 60,
        properties: DictStrObject | None = None,
        will_message: WillMessage | None = None,
    ) -> "Connect":
        if not isinstance(client_id, str):
            raise TypeError()

        if not isinstance(clean_start, bool):
            raise TypeError()

        if username is None and password is not None:
            raise ValueError()
        if username is not None and not isinstance(username, str):
            raise TypeError()
        if password is not None and not isinstance(password, str):
            raise TypeError()

        if not isinstance(keep_alive, int):
            raise TypeError()
        if not (0x0 <= keep_alive <= 0xFFFFFFFF):
            raise ValueError()

        if properties is not None:
            if not isinstance(properties, dict):
                raise TypeError()
            try:
                cls.PROPERTY.encoded_by_name(properties)
            except KeyError:
                raise ValueError()
            except EncodeError:
                raise ValueError()

        if will_message is not None and not isinstance(
            will_message, WillMessage
        ):
            raise TypeError()

        return cls(
            client_id=client_id,
            clean_start=clean_start,
            username=username,
            password=password,
            keep_alive=keep_alive,
            properties=properties,
            will_message=will_message,
        )
