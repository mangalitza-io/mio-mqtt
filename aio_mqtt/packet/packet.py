from abc import ABCMeta, abstractmethod

from aio_mqtt.types import All, DictStrObject

from .codec import (
    encode_one_byte,
    encode_remaining_length,
    encode_string,
    encode_two_byte,
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
    B_PROTOCOL_NAME: bytes = encode_string(PROTOCOL_NAME)

    @classmethod
    @abstractmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        raise NotImplementedError()

    @abstractmethod
    def to_bytes(self) -> bytes:
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
        cls, fixed_byte: int, packet_body: bytes
    ) -> "Packet":
        # TODO fix this.
        pass

    def to_bytes(self) -> bytes:
        packet_type: int = self.TYPE << 4
        protocol_version: bytes = encode_one_byte(5)

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
        b_keep_alive: bytes = encode_two_byte(self._keep_alive)

        b_properties: bytes = encode_one_byte(0)
        if self._properties is not None:
            # TODO
            ...
        # TODO fix in the future cause its bad
        b_will_properties: bytes = encode_one_byte(0)
        if (
            self._will_message is not None
            and self._will_message.properties is not None
        ):
            # TODO
            ...

        b_client_id: bytes = encode_string(self._client_id)

        payload: bytes = b_client_id

        if self._will_message is not None:
            payload += b_will_properties
            payload += self._will_message.b_topic
            payload += self._will_message.b_message

        if self._username is not None:
            payload += encode_string(self._username)

        if self._password is not None:
            payload += encode_string(self._password)

        variable_header: bytes = (
            self.B_PROTOCOL_NAME
            + protocol_version
            + bytes([connect_flags])
            + b_keep_alive
            + b_properties
        )
        remaining_length: int = len(variable_header) + len(payload)
        b_remaining_length: bytes = encode_remaining_length(remaining_length)
        return (
            bytes([packet_type])
            + b_remaining_length
            + variable_header
            + payload
        )


class ConnAckPacket(Packet):
    TYPE: int = 2

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class PublishPacket(Packet):
    TYPE: int = 3

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class PubAckPacket(Packet):
    TYPE: int = 4

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class PubRecPacket(Packet):
    TYPE: int = 5

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class PubRelPacket(Packet):
    TYPE: int = 6

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class PubCompPacket(Packet):
    TYPE: int = 7

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class SubscribePacket(Packet):
    TYPE: int = 8

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class SubAckPacket(Packet):
    TYPE: int = 9

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class UnSubscribePacket(Packet):
    TYPE: int = 10

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class UnSubAckPacket(Packet):
    TYPE: int = 11

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class PingReqPacket(Packet):
    TYPE: int = 12

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class PingRespPacket(Packet):
    TYPE: int = 13

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class DisconnectPacket(Packet):
    TYPE: int = 14

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""


class AuthPacket(Packet):
    TYPE: int = 14

    @classmethod
    def from_bytes(cls, fixed_byte: int, packet_body: bytes) -> "Packet":
        return cls()

    def to_bytes(self) -> bytes:
        return b""
