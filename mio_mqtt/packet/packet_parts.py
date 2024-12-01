from mio_mqtt.packet.codec import StrCodec
from mio_mqtt.packet.properties import (
    CONTENT_TYPE,
    CORRELATION_DATA,
    MESSAGE_EXPIRY_INTERVAL,
    PAYLOAD_FORMAT_ID,
    RESPONSE_TOPIC,
    USER_PROPERTY,
    WILL_DELAY_INTERVAL,
    PropertyCodec,
)
from mio_mqtt.types import All, DictStrObject, Length, Slots

__all__: All = (
    "WillMessage",
    "Subscription",
)


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
        properties: DictStrObject = {},
    ) -> None:
        self.topic: str = topic
        self.message: str = message
        self.qos: int = qos
        self.retain: bool = retain
        self.properties: DictStrObject = properties

        if self.qos not in self.ALLOWED_QOS:
            raise ValueError()

    @property
    def b_properties(self) -> bytearray:
        return self.PROPERTY.encoded_by_name(self.properties)

    @property
    def b_topic(self) -> bytearray:
        return StrCodec.encode(self.topic)

    @property
    def b_message(self) -> bytearray:
        return StrCodec.encode(self.message)


class Subscription:
    """
    NoLocal
        True (1)    Application Messages MUST NOT be forwarded to a
                    connection with a ClientID equal to the ClientID
                    of the publishing connection
    RetainAsPublished
        True (1)    Application Messages forwarded using this
                    subscription keep the RETAIN flag they were published
                    with.
        False (0)   Application Messages forwarded using this
                    subscription have the RETAIN flag set to 0.
                    Retained messages sent when the subscription is
                    established have the RETAIN flag set to 1.
    RetailHandling
        0           Send retained messages at the time of the subscribe
        1           Send retained messages at subscribe only if the
                    subscription does not currently exist
        2           Do not send retained messages at the time of the
                    subscribe
    """

    __slots__: Slots = (
        "_topic",
        "_qos",
        "_no_local",
        "_retain_as_published",
        "_retain_handling",
    )

    def __init__(
        self,
        topic: str,
        qos: int,
        no_local: bool,
        retain_as_published: bool,
        retain_handling: int,
    ) -> None:
        self._topic: str = topic
        self._qos: int = qos
        self._no_local: bool = no_local
        self._retain_as_published: bool = retain_as_published
        self._retain_handling: int = retain_handling

    @classmethod
    def from_bytes(cls, __data: bytearray) -> tuple[Length, "Subscription"]:
        offset: int = 0
        topic_len, topic = StrCodec.decode(__data[offset:])
        offset += topic_len

        subscription_options: int = __data[offset]
        qos: int = subscription_options & 0b11
        no_local: bool = bool((subscription_options >> 2) & 0b1)
        retain_as_published: bool = bool((subscription_options >> 3) & 0b1)
        retain_handling: int = (subscription_options >> 4) & 0b11
        print(f"{subscription_options = }")
        print(f"{topic = }")
        print(f"{qos = }")
        print(f"{no_local = }")
        print(f"{retain_as_published = }")
        print(f"{retain_handling = }")
        return offset + 1, cls(
            topic=topic,
            qos=qos,
            no_local=no_local,
            retain_as_published=retain_as_published,
            retain_handling=retain_handling,
        )

    def to_bytes(self) -> bytearray:
        subscription: bytearray = bytearray()
        subscription.extend(StrCodec.encode(self._topic))

        subscription_options = 0
        subscription_options |= self._qos & 0b11
        subscription_options |= (int(self._no_local) & 0b1) << 2
        subscription_options |= (int(self._retain_as_published) & 0b1) << 3
        subscription_options |= (self._retain_handling & 0b11) << 4
        subscription.append(subscription_options)
        return subscription
