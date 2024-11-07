from select import select

from aio_mqtt.types import DictStrObject


def encode_string(__data: str) -> bytes:
    b_data: bytes = __data.encode("utf-8")
    return len(b_data).to_bytes(length=2, byteorder="big") + b_data


def encode_string_arr(__data: str) -> bytearray:
    b_data: bytes = __data.encode("utf-8")
    res_arr: bytearray = bytearray(2 + len(b_data))
    res_arr[0:2] = len(b_data).to_bytes(length=2, byteorder="big")
    res_arr[2:] = b_data
    return res_arr


def encode_one_byte(__int: int) -> bytes:
    return __int.to_bytes(1, byteorder="big")


def encode_two_byte(__int: int) -> bytes:
    return __int.to_bytes(2, byteorder="big")


def encode_four_byte(__int: int) -> bytes:
    return __int.to_bytes(4, byteorder="big")


def encode_remaining_length(__len: int) -> bytes:
    arr: bytearray = bytearray()
    while True:
        encoded_byte: int = __len % 128
        __len //= 128
        if 0 < __len:
            encoded_byte |= 128
        arr.append(encoded_byte)
        if 0 >= __len:
            break
    return bytes(arr)


class WillMessage:
    ALLOWED_QOS: set[int] = {0, 1, 2}

    def __init__(
        self,
        topic: str,
        message: str,
        qos: int = 0,
        retain: bool = False,
        properties: DictStrObject | None = None,
    ) -> None:
        self.topic: str = topic
        self.message: str = message
        self.qos: int = qos
        self.retain: bool = retain
        self.properties: DictStrObject
        if properties is None:
            self.properties = {}
        else:
            self.properties = properties

        if self.qos not in self.ALLOWED_QOS:
            raise ValueError()

    @property
    def b_topic(self) -> bytes:
        return encode_string(self.topic)

    @property
    def b_message(self) -> bytes:
        return encode_string(self.message)


# ----- # ----- # ----- # ----- # ----- #


class Packet:
    # Mqtt  5.0
    TYPE: int
    PROTOCOL_NAME: str = "MQTT"
    B_PROTOCOL_NAME: bytes = encode_string(PROTOCOL_NAME)


class ConnectPacket(Packet):
    TYPE: int = 1

    @classmethod
    def to_bytes(
        cls,
        client_id: str,
        clean_start: bool = True,
        username: str | None = None,
        password: str | None = None,
        keep_alive: int = 60,
        properties: DictStrObject | None = None,
        will_message: WillMessage | None = None,
    ) -> bytes:
        packet_type: int = cls.TYPE << 4

        protocol_version: bytes = encode_one_byte(5)

        connect_flags: int = 0b00000000
        if clean_start is True:
            connect_flags |= 0b00000010

        if password is not None:
            connect_flags |= 0b01000000

        if username is not None:
            connect_flags |= 0b10000000

        if will_message is not None:
            connect_flags |= 0b00000100
            connect_flags |= will_message.qos << 3
            if will_message.retain is True:
                connect_flags |= 0b00100000

        b_keep_alive: bytes = encode_two_byte(keep_alive)

        b_properties: bytes = encode_one_byte(0)
        if properties is not None:
            # TODO
            pass

        b_will_properties: bytes = encode_one_byte(
            0
        )  # TODO fix in the future cause its bad
        if will_message is not None and will_message.properties is not None:
            # TODO
            pass

        b_client_id: bytes = encode_string(client_id)

        payload: bytes = b_client_id

        if will_message is not None:
            payload += b_will_properties
            payload += will_message.b_topic
            payload += will_message.b_message

        if username is not None:
            payload += encode_string(username)

        if password is not None:
            payload += encode_string(password)

        variable_header: bytes = (
            cls.B_PROTOCOL_NAME
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


class PublishPacket(Packet):
    TYPE: int = 3


class PubAckPacket(Packet):
    TYPE: int = 4


class PubRecPacket(Packet):
    TYPE: int = 5


class PubRelPacket(Packet):
    TYPE: int = 6


class PubCompPacket(Packet):
    TYPE: int = 7


class SubscribePacket(Packet):
    TYPE: int = 8


class SubAckPacket(Packet):
    TYPE: int = 9


class UnSubscribePacket(Packet):
    TYPE: int = 10


class UnSubAckPacket(Packet):
    TYPE: int = 11


class PingReqPacket(Packet):
    TYPE: int = 12


class PingRespPacket(Packet):
    TYPE: int = 13


class DisconnectPacket(Packet):
    TYPE: int = 14


class AuthPacket(Packet):
    TYPE: int = 14
