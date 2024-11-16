from abc import ABCMeta, abstractmethod

from aio_mqtt.types import All, DictStrObject
from .codec import (
    OneByteCodec,
    StrCodec,
    TwoByteCodec,
    encode_remaining_length,
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
        self._properties: DictStrObject | None = properties
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

        b_properties: bytearray = OneByteCodec.encode(0)
        if self._properties is not None:
            # TODO
            ...
        # TODO fix in the future cause its bad
        b_will_properties: bytearray = OneByteCodec.encode(0)
        if (
                self._will_message is not None
                and self._will_message.properties is not None
        ):
            # TODO
            ...

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
        b_remaining_length: bytes = encode_remaining_length(remaining_length)

        packet: bytearray = bytearray()
        packet.append(packet_type)
        packet.extend(b_remaining_length)
        packet.extend(variable_header)
        packet.extend(payload)
        return packet


class ConnAckPacket(Packet):
    TYPE: int = 2

    def __init__(
            self,
            session_present: bool,
            reason_code: int,
            properties: DictStrObject | None = None,
    ) -> None:
        self.session_present: bool = session_present
        self.reason_code: int = reason_code
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
        reason_code = packet_body[1]

        print(f"{session_present}, {reason_code}")
        return cls(
            session_present=session_present,
            reason_code=reason_code,
        )

    def to_bytes(self) -> bytearray:
        return bytearray()


class PublishPacket(Packet):
    TYPE: int = 3

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class PubAckPacket(Packet):
    TYPE: int = 4

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class PubRecPacket(Packet):
    TYPE: int = 5

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class PubRelPacket(Packet):
    TYPE: int = 6

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class PubCompPacket(Packet):
    TYPE: int = 7

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class SubscribePacket(Packet):
    TYPE: int = 8

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class SubAckPacket(Packet):
    TYPE: int = 9

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class UnSubscribePacket(Packet):
    TYPE: int = 10

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class UnSubAckPacket(Packet):
    TYPE: int = 11

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class PingReqPacket(Packet):
    TYPE: int = 12

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class PingRespPacket(Packet):
    TYPE: int = 13

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class DisconnectPacket(Packet):
    TYPE: int = 14

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()


class AuthPacket(Packet):
    TYPE: int = 14

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytearray) -> "Packet":
        return cls()

    def to_bytes(self) -> bytearray:
        return bytearray()
