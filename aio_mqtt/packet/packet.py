from abc import ABCMeta, abstractmethod

from aio_mqtt.types import All, DictStrObject, Length

from .codec import OneByteCodec, StrCodec, TwoByteCodec, VariableByteCodec
from .properties import (
    ASSIGNED_CLIENT_IDENTIFIER,
    AUTH_DATA,
    AUTH_METHOD,
    CONTENT_TYPE,
    CORRELATION_DATA,
    MAX_QOS,
    MAXIMUM_PACKET_SIZE,
    MESSAGE_EXPIRY_INTERVAL,
    PAYLOAD_FORMAT_ID,
    REASON_STRING,
    RECEIVE_MAXIMUM,
    REQUEST_PROBLEM_INFO,
    REQUEST_RESPONSE_INFO,
    RESPONSE_INFO,
    RESPONSE_TOPIC,
    RETAIN_AVAILABLE,
    SERVER_KEEP_ALIVE,
    SERVER_REFERENCE,
    SESSION_EXPIRY_INTERVAL,
    SHARED_SUBSCRIPTION_AVAILABLE,
    SUB_ID_AVAILABLE,
    SUBSCRIPTION_IDENTIFIER,
    TOPIC_ALIAS,
    TOPIC_ALIAS_MAXIMUM,
    USER_PROPERTY,
    WILDCARD_SUBSCRIPTION_AVAILABLE,
    Property,
    PropertyCodec,
)
from .reason_codes import (
    ADMINISTRATIVE_ACTION,
    BAD_AUTHENTICATION_METHOD,
    BAD_USER_NAME_OR_PASSWORD,
    BANNED,
    CLIENT_IDENTIFIER_NOT_VALID,
    CONNECTION_RATE_EXCEEDED,
    CONTINUE_AUTHENTICATION,
    DISCONNECT_WITH_WILL_MESSAGE,
    GRANTED_QOS_0,
    GRANTED_QOS_1,
    GRANTED_QOS_2,
    IMPLEMENTATION_SPECIFIC_ERROR,
    KEEP_ALIVE_TIMEOUT,
    MALFORMED_PACKET,
    MAXIMUM_CONNECT_TIME,
    MESSAGE_RATE_TOO_HIGH,
    NO_MATCHING_SUBSCRIBERS,
    NO_SUBSCRIPTION_EXISTED,
    NORMAL_DISCONNECTION,
    NOT_AUTHORIZED,
    PACKET_IDENTIFIER_IN_USE,
    PACKET_IDENTIFIER_NOT_FOUND,
    PACKET_TOO_LARGE,
    PAYLOAD_FORMAT_INVALID,
    PROTOCOL_ERROR,
    QOS_NOT_SUPPORTED,
    QUOTA_EXCEEDED,
    RE_AUTHENTICATE,
    RECEIVE_MAXIMUM_EXCEEDED,
    RETAIN_NOT_SUPPORTED,
    SERVER_BUSY,
    SERVER_MOVED,
    SERVER_SHUTTING_DOWN,
    SERVER_UNAVAILABLE,
    SESSION_TAKEN_OVER,
    SHARED_SUBSCRIPTIONS_NOT_SUPPORTED,
    SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED,
    SUCCESS,
    TOPIC_ALIAS_INVALID,
    TOPIC_FILTER_INVALID,
    TOPIC_NAME_INVALID,
    UNSPECIFIED_ERROR,
    UNSUPPORTED_PROTOCOL_VERSION,
    USE_ANOTHER_SERVER,
    WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED,
    ReasonCode,
    ReasonCodes,
)
from .will import WillMessage

__all__: All = (
    "Packet",
    "ConnectPacket",
    "ConnAckPacket",
    "PublishPacket",
    "PubAckPacket",
    "PubRecPacket",
    "PubRelPacket",
    "PubCompPacket",
    "SubscribePacket",
    "SubAckPacket",
    "UnSubscribePacket",
    "UnSubAckPacket",
    "PingReqPacket",
    "PingRespPacket",
    "DisconnectPacket",
    "AuthPacket",
)


class Packet(metaclass=ABCMeta):
    # Mqtt  5.0
    TYPE: int
    PROTOCOL_NAME: str = "MQTT"
    B_PROTOCOL_NAME: bytearray = StrCodec.encode(PROTOCOL_NAME)

    @classmethod
    @abstractmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        raise NotImplementedError()

    @abstractmethod
    def to_bytes(self) -> bytearray:
        raise NotImplementedError()


class ConnectPacket(Packet):
    TYPE: int = 1
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            SESSION_EXPIRY_INTERVAL,
            AUTH_METHOD,
            AUTH_DATA,
            REQUEST_PROBLEM_INFO,
            REQUEST_RESPONSE_INFO,
            RECEIVE_MAXIMUM,
            TOPIC_ALIAS_MAXIMUM,
            USER_PROPERTY,
            MAXIMUM_PACKET_SIZE,
        )
    )

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
        self._client_id: str = client_id
        self._clean_start: bool = clean_start
        self._username: str | None = username
        self._password: str | None = password
        self._keep_alive: int = keep_alive

        self._properties: DictStrObject
        if properties is not None:
            self._properties = properties
        else:
            self._properties = {}
        self._will_message: WillMessage | None = will_message

    @classmethod
    def from_bytes(  # type: ignore[empty-body]
        cls, fixed_byte: int, packet_body: bytearray
    ) -> "Packet":
        # TODO fix this.
        pass

    def to_bytes(self) -> bytearray:
        packet_type: int = self.TYPE << 4
        protocol_version: bytearray = OneByteCodec.encode(5)

        connect_flags: int = 0b00000000
        if self._clean_start is True:
            connect_flags |= 0b00000010

        if self._password is not None:
            connect_flags |= 0b01000000

        if self._username is not None:
            connect_flags |= 0b10000000

        if self._will_message is not None:
            connect_flags |= 0b00000100
            connect_flags |= self._will_message.qos << 3
            if self._will_message.retain is True:
                connect_flags |= 0b00100000
        b_keep_alive: bytes = TwoByteCodec.encode(self._keep_alive)

        b_properties: bytearray = self.PROPERTY.encoded_by_name(
            self._properties
        )

        b_will_properties: bytearray = VariableByteCodec.encode(0)
        if (
            self._will_message is not None
            and self._will_message.properties is not None
        ):
            b_will_properties = self._will_message.b_properties

        b_client_id: bytearray = StrCodec.encode(self._client_id)

        payload: bytearray = bytearray()
        payload.extend(b_client_id)

        if self._will_message is not None:
            payload += b_will_properties
            payload += StrCodec.encode(self._will_message.topic)
            payload += StrCodec.encode(self._will_message.message)

        if self._username is not None:
            payload += StrCodec.encode(self._username)

        if self._password is not None:
            payload += StrCodec.encode(self._password)

        variable_header: bytearray = bytearray()
        variable_header.extend(self.B_PROTOCOL_NAME)
        variable_header.extend(protocol_version)
        variable_header.append(connect_flags)
        variable_header.extend(b_keep_alive)
        variable_header.extend(b_properties)

        remaining_length: int = len(variable_header) + len(payload)
        b_remaining_length: bytes = VariableByteCodec.encode(remaining_length)

        packet: bytearray = bytearray()
        packet.append(packet_type)
        packet.extend(b_remaining_length)
        packet.extend(variable_header)
        packet.extend(payload)
        return packet


class ConnAckPacket(Packet):
    TYPE: int = 2
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            SESSION_EXPIRY_INTERVAL,
            ASSIGNED_CLIENT_IDENTIFIER,
            SERVER_KEEP_ALIVE,
            AUTH_METHOD,
            AUTH_DATA,
            RESPONSE_INFO,
            SERVER_REFERENCE,
            REASON_STRING,
            RECEIVE_MAXIMUM,
            TOPIC_ALIAS_MAXIMUM,
            MAX_QOS,
            RETAIN_AVAILABLE,
            USER_PROPERTY,
            MAXIMUM_PACKET_SIZE,
            WILDCARD_SUBSCRIPTION_AVAILABLE,
            SUB_ID_AVAILABLE,
            SHARED_SUBSCRIPTION_AVAILABLE,
        )
    )
    REASON_CODE: ReasonCodes = ReasonCodes(
        (
            SUCCESS,
            UNSPECIFIED_ERROR,
            MALFORMED_PACKET,
            PROTOCOL_ERROR,
            IMPLEMENTATION_SPECIFIC_ERROR,
            UNSUPPORTED_PROTOCOL_VERSION,
            CLIENT_IDENTIFIER_NOT_VALID,
            BAD_USER_NAME_OR_PASSWORD,
            NOT_AUTHORIZED,
            SERVER_UNAVAILABLE,
            SERVER_BUSY,
            BANNED,
            BAD_AUTHENTICATION_METHOD,
            TOPIC_NAME_INVALID,
            PACKET_TOO_LARGE,
            QUOTA_EXCEEDED,
            PAYLOAD_FORMAT_INVALID,
            RETAIN_NOT_SUPPORTED,
            QOS_NOT_SUPPORTED,
            USE_ANOTHER_SERVER,
            SERVER_MOVED,
            CONNECTION_RATE_EXCEEDED,
        )
    )

    def __init__(
        self,
        session_present: bool,
        reason_code: ReasonCode,
        properties: DictStrObject | None = None,
    ) -> None:
        self.session_present: bool = session_present
        self.reason_code: ReasonCode = reason_code

        self.properties: DictStrObject
        if properties is None:
            self.properties = {}
        else:
            self.properties = properties

    @classmethod
    def from_bytes(
        cls, fixed_byte: int, packet_body: bytearray
    ) -> "ConnAckPacket":
        session_present = bool(packet_body[0] & 0b00000001)
        reason_code = cls.REASON_CODE[packet_body[1]]
        properties_len, properties = cls.PROPERTY.decode_for_name(
            packet_body[2:]
        )
        return cls(
            session_present=session_present,
            reason_code=reason_code,
            properties=properties,
        )

    def to_bytes(self) -> bytearray:
        return bytearray()


class PublishPacket(Packet):
    TYPE: int = 3
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            PAYLOAD_FORMAT_ID,
            MESSAGE_EXPIRY_INTERVAL,
            CONTENT_TYPE,
            RESPONSE_TOPIC,
            CORRELATION_DATA,
            SUBSCRIPTION_IDENTIFIER,
            TOPIC_ALIAS,
            USER_PROPERTY,
        )
    )
    ALLOWED_QOS: set[int] = {0, 1, 2}

    def __init__(
        self,
        dup: bool,
        qos: int,
        retain: bool,
        topic: str,
        packet_id: int | None = None,
        properties: DictStrObject | None = None,
        payload: bytes | bytearray = b"",
    ) -> None:
        self._dup: bool = dup
        self._qos: int = qos
        self._retain: bool = retain
        self._topic: str = topic
        self._packet_id: int | None = packet_id

        self._properties: DictStrObject
        if properties is not None:
            self._properties = properties
        else:
            self._properties = {}
        self._payload: bytes | bytearray = payload

        if self._qos not in self.ALLOWED_QOS:
            raise ValueError()

    def to_bytes(self) -> bytearray:
        fixed_header: int = self.TYPE << 4
        fixed_header |= int(self._dup) << 3
        fixed_header |= (self._qos & 0x03) << 1
        fixed_header |= int(self._retain)

        variable_header: bytearray = bytearray()
        variable_header.extend(StrCodec.encode(self._topic))

        if 0 < self._qos:
            variable_header.extend(TwoByteCodec.encode(self._qos))
        variable_header.extend(
            self.PROPERTY.encoded_by_name(properties=self._properties)
        )

        remaining_length: int = len(variable_header) + len(self._payload)
        b_remaining_length: bytes = VariableByteCodec.encode(remaining_length)

        packet: bytearray = bytearray()
        packet.append(fixed_header)
        packet.extend(b_remaining_length)
        packet.extend(variable_header)
        packet.extend(self._payload)
        return packet

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        dup: bool = bool((fixed_byte >> 3) & 0x01)
        qos: int = (fixed_byte >> 1) & 0x03
        retain: bool = bool(fixed_byte & 0x01)

        offset: int = 0

        topic_len, topic = StrCodec.decode(packet_body[offset:])
        offset += topic_len

        packet_id: int | None = None
        if 0 < qos:
            packet_id_len, packet_id = TwoByteCodec.decode(
                packet_body[offset:]
            )
            offset += packet_id_len

        properties_len, properties = cls.PROPERTY.decode_for_name(
            packet_body[offset:]
        )
        offset += properties_len

        payload: bytearray = packet_body[offset:]

        return cls(
            dup=dup,
            qos=qos,
            retain=retain,
            topic=topic,
            packet_id=packet_id,
            properties=properties,
            payload=payload,
        )


class PubAckPacket(Packet):
    TYPE: int = 4
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            REASON_STRING,
            USER_PROPERTY,
        )
    )
    REASON_CODE: ReasonCodes = ReasonCodes(
        (
            SUCCESS,
            NO_MATCHING_SUBSCRIBERS,
            UNSPECIFIED_ERROR,
            IMPLEMENTATION_SPECIFIC_ERROR,
            NOT_AUTHORIZED,
            TOPIC_NAME_INVALID,
            PACKET_IDENTIFIER_IN_USE,
            QUOTA_EXCEEDED,
            PAYLOAD_FORMAT_INVALID,
        )
    )

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class PubRecPacket(Packet):
    TYPE: int = 5
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            REASON_STRING,
            USER_PROPERTY,
        )
    )
    REASON_CODE: ReasonCodes = ReasonCodes(
        (
            SUCCESS,
            NO_MATCHING_SUBSCRIBERS,
            UNSPECIFIED_ERROR,
            IMPLEMENTATION_SPECIFIC_ERROR,
            NOT_AUTHORIZED,
            TOPIC_NAME_INVALID,
            PACKET_IDENTIFIER_IN_USE,
            QUOTA_EXCEEDED,
            PAYLOAD_FORMAT_INVALID,
        )
    )

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class PubRelPacket(Packet):
    TYPE: int = 6
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            REASON_STRING,
            USER_PROPERTY,
        )
    )
    REASON_CODE: ReasonCodes = ReasonCodes(
        (
            SUCCESS,
            PACKET_IDENTIFIER_NOT_FOUND,
            UNSPECIFIED_ERROR,
            IMPLEMENTATION_SPECIFIC_ERROR,
            NOT_AUTHORIZED,
        )
    )

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class PubCompPacket(Packet):
    TYPE: int = 7
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            REASON_STRING,
            USER_PROPERTY,
        )
    )
    REASON_CODE: ReasonCodes = ReasonCodes(
        (
            SUCCESS,
            PACKET_IDENTIFIER_NOT_FOUND,
            UNSPECIFIED_ERROR,
            IMPLEMENTATION_SPECIFIC_ERROR,
        )
    )

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class SubscribePacket(Packet):
    TYPE: int = 8
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            SUBSCRIPTION_IDENTIFIER,
            USER_PROPERTY,
        )
    )

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class SubAckPacket(Packet):
    TYPE: int = 9
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            REASON_STRING,
            USER_PROPERTY,
        )
    )
    REASON_CODE: ReasonCodes = ReasonCodes(
        (
            GRANTED_QOS_0,
            GRANTED_QOS_1,
            GRANTED_QOS_2,
            UNSPECIFIED_ERROR,
            IMPLEMENTATION_SPECIFIC_ERROR,
            NOT_AUTHORIZED,
            TOPIC_FILTER_INVALID,
            QOS_NOT_SUPPORTED,
            SHARED_SUBSCRIPTIONS_NOT_SUPPORTED,
            SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED,
            WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED,
        )
    )

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class UnSubscribePacket(Packet):
    TYPE: int = 10
    PROPERTY: PropertyCodec = PropertyCodec((USER_PROPERTY,))

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class UnSubAckPacket(Packet):
    TYPE: int = 11
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            REASON_STRING,
            USER_PROPERTY,
        )
    )
    REASON_CODE: ReasonCodes = ReasonCodes(
        (
            SUCCESS,
            NO_SUBSCRIPTION_EXISTED,
            UNSPECIFIED_ERROR,
            IMPLEMENTATION_SPECIFIC_ERROR,
            NOT_AUTHORIZED,
            TOPIC_FILTER_INVALID,
        )
    )

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class PingReqPacket(Packet):
    TYPE: int = 12
    PROPERTY: PropertyCodec = PropertyCodec(())

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class PingRespPacket(Packet):
    TYPE: int = 13
    PROPERTY: PropertyCodec = PropertyCodec(())

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class DisconnectPacket(Packet):
    TYPE: int = 14
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            SESSION_EXPIRY_INTERVAL,
            REASON_STRING,
            USER_PROPERTY,
            SERVER_REFERENCE,
        )
    )
    REASON_CODE: ReasonCodes = ReasonCodes(
        (
            NORMAL_DISCONNECTION,
            DISCONNECT_WITH_WILL_MESSAGE,
            UNSPECIFIED_ERROR,
            MALFORMED_PACKET,
            PROTOCOL_ERROR,
            IMPLEMENTATION_SPECIFIC_ERROR,
            NOT_AUTHORIZED,
            SERVER_BUSY,
            SERVER_SHUTTING_DOWN,
            BAD_AUTHENTICATION_METHOD,
            KEEP_ALIVE_TIMEOUT,
            SESSION_TAKEN_OVER,
            TOPIC_FILTER_INVALID,
            TOPIC_NAME_INVALID,
            RECEIVE_MAXIMUM_EXCEEDED,
            TOPIC_ALIAS_INVALID,
            PACKET_TOO_LARGE,
            MESSAGE_RATE_TOO_HIGH,
            QUOTA_EXCEEDED,
            ADMINISTRATIVE_ACTION,
            PAYLOAD_FORMAT_INVALID,
            RETAIN_NOT_SUPPORTED,
            QOS_NOT_SUPPORTED,
            USE_ANOTHER_SERVER,
            SERVER_MOVED,
            CONNECTION_RATE_EXCEEDED,
            MAXIMUM_CONNECT_TIME,
            SHARED_SUBSCRIPTIONS_NOT_SUPPORTED,
            SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED,
            WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED,
        )
    )

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class AuthPacket(Packet):
    TYPE: int = 14
    PROPERTY: PropertyCodec = PropertyCodec(
        (
            AUTH_METHOD,
            AUTH_DATA,
            REASON_STRING,
            USER_PROPERTY,
        )
    )
    REASON_CODE: ReasonCodes = ReasonCodes(
        (
            SUCCESS,
            CONTINUE_AUTHENTICATION,
            RE_AUTHENTICATE,
            UNSPECIFIED_ERROR,
        )
    )

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()
