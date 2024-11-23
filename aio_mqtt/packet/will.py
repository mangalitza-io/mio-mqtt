from aio_mqtt.packet.codec import StrCodec
from aio_mqtt.packet.properties import (
    CONTENT_TYPE,
    CORRELATION_DATA,
    MESSAGE_EXPIRY_INTERVAL,
    PAYLOAD_FORMAT_ID,
    RESPONSE_TOPIC,
    USER_PROPERTY,
    WILL_DELAY_INTERVAL,
    PropertyCodec,
)
from aio_mqtt.types import All, DictStrObject, Slots

__all__: All = ("WillMessage",)


class WillMessage:
    DEFAULT_QOS: int = 0
    DEFAULT_RETAIN: bool = False
    ALLOWED_QOS: set[int] = {0, 1, 2}
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            PAYLOAD_FORMAT_ID,
            MESSAGE_EXPIRY_INTERVAL,
            CONTENT_TYPE,
            RESPONSE_TOPIC,
            CORRELATION_DATA,
            USER_PROPERTY,
            WILL_DELAY_INTERVAL,
        )
    )
    __slots__: Slots = (
        "topic",
        "message",
        "qos",
        "retain",
        "properties",
    )

    def __init__(
        self,
        topic: str,
        message: str,
        qos: int = DEFAULT_QOS,
        retain: bool = DEFAULT_RETAIN,
        properties: DictStrObject | None = None,
    ) -> None:
        self.topic: str = topic
        self.message: str = message
        self.qos: int = qos
        self.retain: bool = retain

        self.properties: DictStrObject
        if properties is not None:
            self.properties = properties
        else:
            self.properties = {}

        if self.qos not in self.ALLOWED_QOS:
            raise ValueError()

    @property
    def b_topic(self) -> bytearray:
        return StrCodec.encode(self.topic)

    @property
    def b_message(self) -> bytearray:
        return StrCodec.encode(self.message)

    @property
    def b_properties(self) -> bytearray:
        return self.PROPERTY.encoded_by_name(self.properties)
