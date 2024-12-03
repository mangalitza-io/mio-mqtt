from typing import cast

import pytest
from pytest_mock import MockFixture

from mio_mqtt.packet.codec import (
    OneByteCodec,
    StrCodec,
    TwoByteCodec,
    VariableByteCodec,
)
from mio_mqtt.packet.packet import (
    AuthPacket,
    ConnAckPacket,
    ConnectPacket,
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
    SubscribePacket,
    UnSubAckPacket,
    UnSubscribePacket,
)
from mio_mqtt.packet.packet_parts import Subscription, WillMessage
from mio_mqtt.packet.properties import (
    CONTENT_TYPE,
    MAX_QOS,
    REASON_STRING,
    USER_PROPERTY,
)
from mio_mqtt.packet.reason_codes import (
    GRANTED_QOS_0,
    NORMAL_DISCONNECTION,
    SUCCESS,
    ReasonCode,
)
from mio_mqtt.types import DictStrObject


def to_decode(__arr: bytearray) -> tuple[int, bytearray]:
    first_byte: int = __arr[0]
    body_size_length, _ = VariableByteCodec.decode(__arr[1:])
    return first_byte, __arr[1 + body_size_length :]


def to_byte_reconstruct(packet: Packet) -> Packet:
    packet_bytes: bytearray = packet.to_bytes()
    first_byte, packet_body = to_decode(packet_bytes)
    return type(packet).from_bytes(first_byte, packet_body)


class TestPacket:
    fixed_byte: int
    variable_header: bytes | bytearray
    payload: bytes | bytearray
    packet_body: bytes | bytearray

    @classmethod
    def setup_class(cls) -> None:
        cls.fixed_byte = 0x00
        cls.variable_header = b"header"
        cls.payload = b"payload"

    def test_packet_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            Packet()  # type: ignore[abstract]

    def test_from_bytes_is_abstract(self) -> None:
        with pytest.raises(NotImplementedError):
            Packet.from_bytes(
                fixed_byte=self.fixed_byte, packet_body=bytearray()
            )

    def test_to_bytes_is_abstract(self, mocker: MockFixture) -> None:
        with pytest.raises(NotImplementedError):
            Packet.to_bytes(mocker)  # type: ignore[arg-type]

    def test_remaining_length_empty(self) -> None:
        result = Packet._remaining_length()
        expected = VariableByteCodec.encode(0)
        assert result == expected

    def test_remaining_length_variable_header_only(self) -> None:
        result = Packet._remaining_length(variable_header=self.variable_header)
        expected = VariableByteCodec.encode(len(self.variable_header))
        assert result == expected

    def test_remaining_length_payload_only(self) -> None:
        result = Packet._remaining_length(payload=self.payload)
        expected = VariableByteCodec.encode(len(self.payload))
        assert result == expected

    def test_remaining_length_combined(self) -> None:
        result = Packet._remaining_length(
            variable_header=self.variable_header, payload=self.payload
        )
        expected = VariableByteCodec.encode(
            len(self.variable_header) + len(self.payload)
        )
        assert result == expected

    def test_fixed_header_empty(self) -> None:
        result = Packet._fixed_header(first_byte=self.fixed_byte)
        expected = bytearray([self.fixed_byte])
        expected += VariableByteCodec.encode(0)
        assert result == expected

    def test_to_packet_empty(self) -> None:
        result = Packet._to_packet(self.fixed_byte)
        expected_fixed_header = Packet._fixed_header(self.fixed_byte)
        assert result == expected_fixed_header

    def test_fixed_header_basic(self) -> None:
        result = Packet._fixed_header(
            self.fixed_byte, self.variable_header, self.payload
        )
        expected_length = VariableByteCodec.encode(
            len(self.variable_header) + len(self.payload)
        )

        assert result[0] == self.fixed_byte
        assert result[1:] == expected_length

    def test_to_packet_with_variable_header(self) -> None:
        result = Packet._to_packet(
            self.fixed_byte, variable_header=self.variable_header
        )
        expected_fixed_header = Packet._fixed_header(
            self.fixed_byte, variable_header=self.variable_header
        )
        expected_packet = expected_fixed_header + self.variable_header
        assert result == expected_packet

    def test_to_packet_with_payload(self) -> None:
        result = Packet._to_packet(self.fixed_byte, payload=self.payload)
        expected_fixed_header = Packet._fixed_header(
            self.fixed_byte, payload=self.payload
        )
        expected_packet = expected_fixed_header + self.payload
        assert result == expected_packet

    def test_to_packet_with_variable_header_and_payload(self) -> None:
        result = Packet._to_packet(
            self.fixed_byte,
            variable_header=self.variable_header,
            payload=self.payload,
        )
        expected_fixed_header = Packet._fixed_header(
            self.fixed_byte,
            variable_header=self.variable_header,
            payload=self.payload,
        )
        expected_packet = (
            expected_fixed_header + self.variable_header + self.payload
        )
        assert result == expected_packet


class TestConnectPacket:
    client_id: str
    clean_start: bool
    username: str
    password: str
    keep_alive: int
    properties: DictStrObject
    will_message: WillMessage

    flags_i: int

    packet: ConnectPacket
    packet_with_properties: ConnectPacket
    packet_custom: ConnectPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.client_id = "test_client"
        cls.clean_start = False
        cls.username = "user"
        cls.password = "pass"
        cls.keep_alive = 30
        cls.properties = {USER_PROPERTY.name: ("apple", "one")}
        cls.will_message = WillMessage(
            topic="topic",
            message="message",
            qos=1,
            retain=True,
            properties={},
        )
        cls.flags_i = len(ConnectPacket.B_PROTOCOL_NAME) + len(
            OneByteCodec.encode(ConnectPacket.MQTT_50)
        )

        cls.packet = ConnectPacket(client_id=cls.client_id)
        cls.packet_with_properties = ConnectPacket(
            client_id=cls.client_id,
            properties=cls.properties,
        )
        cls.packet_custom = ConnectPacket(
            client_id=cls.client_id,
            clean_start=cls.clean_start,
            username=cls.username,
            password=cls.password,
            keep_alive=cls.keep_alive,
            properties=cls.properties,
            will_message=cls.will_message,
        )

    def test_connect_packet_is_subclass_of_packet(self) -> None:
        assert issubclass(ConnectPacket, Packet)

    def test_connect_packet_init_default(self) -> None:
        assert self.packet._client_id == self.client_id
        assert self.packet._clean_start is True
        assert self.packet._username is None
        assert self.packet._password is None
        assert self.packet._keep_alive == 60
        assert self.packet._properties == {}
        assert self.packet._will_message is None

    def test_connect_packet_init_with_property(self) -> None:
        assert self.packet_with_properties._client_id == self.client_id
        assert self.packet_with_properties._clean_start is True
        assert self.packet_with_properties._username is None
        assert self.packet_with_properties._password is None
        assert self.packet_with_properties._keep_alive == 60
        assert self.packet_with_properties._properties == self.properties
        assert self.packet_with_properties._will_message is None

    def test_connect_packet_custom_init(self) -> None:
        assert self.packet_custom._client_id == self.client_id
        assert self.packet_custom._clean_start is self.clean_start
        assert self.packet_custom._username == self.username
        assert self.packet_custom._password == self.password
        assert self.packet_custom._keep_alive == self.keep_alive
        assert self.packet_custom._properties == self.properties
        assert self.packet_custom._will_message == self.will_message

    def test_connect_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)

    def test_connect_packet_to_bytes_with_clean_start(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert packet_body[self.flags_i] & 0b00000010 != 0

    def test_connect_packet_to_bytes_with_username_password(self) -> None:
        packet_bytes: bytearray = self.packet_custom.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert packet_body[self.flags_i] & 0b10000000 != 0
        assert packet_body[self.flags_i] & 0b01000000 != 0

    def test_connect_packet_to_bytes_with_will_message(self) -> None:
        packet_bytes: bytearray = self.packet_custom.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert packet_body[self.flags_i] & 0b00000100 != 0
        assert packet_body[self.flags_i] & 0b00100000 != 0

    def test_connect_packet_from_bytes_basic(self) -> None:
        reconstructed: ConnectPacket = cast(
            ConnectPacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._client_id == self.client_id

    def test_connect_packet_from_bytes_with_username_password(self) -> None:
        reconstructed: ConnectPacket = cast(
            ConnectPacket, to_byte_reconstruct(self.packet_custom)
        )

        assert reconstructed._username == self.username
        assert reconstructed._password == self.password

    def test_connect_packet_from_bytes_with_will_message(self) -> None:
        reconstructed: ConnectPacket = cast(
            ConnectPacket, to_byte_reconstruct(self.packet_custom)
        )
        reconstructed_will_message: WillMessage = cast(
            WillMessage, reconstructed._will_message
        )
        assert reconstructed_will_message.topic == self.will_message.topic
        assert reconstructed_will_message.message == self.will_message.message
        assert reconstructed_will_message.qos == self.will_message.qos
        assert reconstructed_will_message.retain == self.will_message.retain
        assert (
            reconstructed_will_message.properties
            == self.will_message.properties
        )


class TestConnAckPacket:
    session_present: bool
    reason_code: ReasonCode
    properties: DictStrObject

    packet: ConnAckPacket
    packet_with_properties: ConnAckPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.session_present = False
        cls.reason_code = SUCCESS
        cls.properties = {MAX_QOS.name: 2}

        cls.packet = ConnAckPacket(
            session_present=cls.session_present,
            reason_code=cls.reason_code,
        )
        cls.packet_with_properties = ConnAckPacket(
            session_present=cls.session_present,
            reason_code=cls.reason_code,
            properties=cls.properties,
        )

    def test_conn_ack_packet_defaults(self) -> None:
        assert self.packet._session_present is self.session_present
        assert self.packet._reason_code == self.reason_code
        assert self.packet._properties == {}

    def test_conn_ack_packet_with_properties_init(self) -> None:
        assert (
            self.packet_with_properties._session_present
            is self.session_present
        )
        assert self.packet_with_properties._reason_code == self.reason_code
        assert self.packet_with_properties._properties == self.properties

    def test_conn_ack_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0] == int(self.session_present)
        assert packet_body[1] == self.reason_code.code

    def test_conn_ack_packet_with_properties(self) -> None:
        packet_bytes: bytearray = self.packet_with_properties.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0] == int(self.session_present)
        assert packet_body[1] == self.reason_code.code
        assert len(packet_body) > 2

    def test_conn_ack_packet_from_bytes_basic(self) -> None:
        reconstructed: ConnAckPacket = cast(
            ConnAckPacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._session_present == self.packet._session_present
        assert reconstructed._reason_code == self.packet._reason_code
        assert reconstructed._properties == self.packet._properties


class TestPublishPacket:
    dup: bool
    qos_0: int
    qos_1: int
    retain: bool
    topic: str
    packet_id: int
    properties: DictStrObject
    payload: bytes | bytearray

    packet: PublishPacket
    packet_custom: PublishPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.dup = False
        cls.qos_0 = 0
        cls.qos_1 = 1
        cls.retain = False
        cls.topic = "test/topic"
        cls.packet_id = 123
        cls.properties = {CONTENT_TYPE.name: "value"}
        cls.payload = b"test_payload"

        cls.packet = PublishPacket(
            dup=cls.dup,
            qos=cls.qos_0,
            retain=cls.retain,
        )
        cls.packet_custom = PublishPacket(
            dup=cls.dup,
            qos=cls.qos_1,
            retain=cls.retain,
            topic=cls.topic,
            packet_id=cls.packet_id,
            properties=cls.properties,
            payload=cls.payload,
        )

    def test_publish_packet_defaults(self) -> None:
        assert self.packet._dup is self.dup
        assert self.packet._qos == self.qos_0
        assert self.packet._retain is self.retain
        assert self.packet._topic is ""
        assert self.packet._packet_id is None
        assert self.packet._properties == {}
        assert self.packet._payload == b""

    def test_publish_packet_init_with_values(self) -> None:
        assert self.packet_custom._dup is self.dup
        assert self.packet_custom._qos == self.qos_1
        assert self.packet_custom._retain is self.retain
        assert self.packet_custom._topic == self.topic
        assert self.packet_custom._packet_id == self.packet_id
        assert self.packet_custom._properties == self.properties
        assert self.packet_custom._payload == self.payload

    def test_publish_packet_invalid_qos(self) -> None:
        with pytest.raises(ValueError):
            PublishPacket(dup=False, qos=100, retain=False)

    def test_publish_packet_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)

    def test_publish_packet_with_qos(self) -> None:
        packet_bytes: bytearray = self.packet_custom.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte & 0b00000110 != 0

    def test_publish_packet_without_packet_id(self) -> None:
        packet = PublishPacket(
            dup=False, qos=1, retain=False, topic="test/topic"
        )
        with pytest.raises(ValueError):
            packet.to_bytes()

    def test_publish_packet_from_bytes_basic(self) -> None:
        reconstructed: PublishPacket = cast(
            PublishPacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._dup == self.packet._dup
        assert reconstructed._qos == self.packet._qos
        assert reconstructed._retain == self.packet._retain
        assert reconstructed._topic == self.packet._topic
        assert reconstructed._payload == self.packet._payload

    def test_publish_packet_from_bytes_with_qos(self) -> None:
        reconstructed: PublishPacket = cast(
            PublishPacket, to_byte_reconstruct(self.packet_custom)
        )

        assert reconstructed._dup == self.packet_custom._dup
        assert reconstructed._qos == self.packet_custom._qos
        assert reconstructed._retain == self.packet_custom._retain
        assert reconstructed._topic == self.packet_custom._topic
        assert reconstructed._packet_id == self.packet_custom._packet_id
        assert reconstructed._payload == self.packet_custom._payload

    def test_publish_packet_from_bytes_with_properties(self) -> None:
        reconstructed: PublishPacket = cast(
            PublishPacket, to_byte_reconstruct(self.packet_custom)
        )

        assert reconstructed._dup == self.packet_custom._dup
        assert reconstructed._qos == self.packet_custom._qos
        assert reconstructed._retain == self.packet_custom._retain
        assert reconstructed._topic == self.packet_custom._topic
        assert reconstructed._packet_id == self.packet_custom._packet_id
        assert reconstructed._properties == self.packet_custom._properties


class TestPubAckPacket:
    packet_id: int
    reason_code: ReasonCode
    properties: DictStrObject

    packet: PubAckPacket
    packet_with_properties: PubAckPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.packet_id = 123
        cls.reason_code = SUCCESS
        cls.properties = {REASON_STRING.name: "value"}

        cls.packet = PubAckPacket(
            packet_id=cls.packet_id,
            reason_code=cls.reason_code,
        )
        cls.packet_with_properties = PubAckPacket(
            packet_id=cls.packet_id,
            reason_code=cls.reason_code,
            properties=cls.properties,
        )

    def test_pub_ack_packet_init_defaults(self) -> None:
        assert self.packet._packet_id == self.packet_id
        assert self.packet._reason_code == self.reason_code
        assert self.packet._properties == {}

    def test_pub_ack_packet_init_with_properties(self) -> None:
        assert self.packet_with_properties._packet_id == self.packet_id
        assert self.packet_with_properties._reason_code == self.reason_code
        assert self.packet_with_properties._properties == self.properties

    def test_pub_ack_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == self.reason_code.code

    def test_pub_ack_packet_to_bytes_with_properties(self) -> None:
        packet_bytes: bytearray = self.packet_with_properties.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet_with_properties.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == self.reason_code.code
        assert len(packet_body) > 3

    def test_pub_ack_packet_from_bytes_basic(self) -> None:
        reconstructed: PubAckPacket = cast(
            PubAckPacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._packet_id == self.packet._packet_id
        assert reconstructed._reason_code == self.packet._reason_code
        assert reconstructed._properties == self.packet._properties

    def test_pub_ack_packet_from_bytes_with_properties(self) -> None:
        reconstructed: PubAckPacket = cast(
            PubAckPacket, to_byte_reconstruct(self.packet_with_properties)
        )

        assert (
            reconstructed._packet_id == self.packet_with_properties._packet_id
        )
        assert (
            reconstructed._reason_code
            == self.packet_with_properties._reason_code
        )
        assert (
            reconstructed._properties
            == self.packet_with_properties._properties
        )

    def test_pub_ack_packet_invalid_reason_code(self) -> None:
        invalid_reason_code = 255
        packet_body: bytearray = bytearray()
        packet_body += TwoByteCodec.encode(123)  # packet id
        packet_body += OneByteCodec.encode(invalid_reason_code)
        packet_body += OneByteCodec.encode(0)

        with pytest.raises(KeyError):
            PubAckPacket.from_bytes(0x40, packet_body)


class TestPubRecPacket:
    packet_id: int
    reason_code: ReasonCode
    properties: DictStrObject

    packet: PubRecPacket
    packet_with_properties: PubRecPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.packet_id = 123
        cls.reason_code = SUCCESS
        cls.properties = {REASON_STRING.name: "value"}

        cls.packet = PubRecPacket(
            packet_id=cls.packet_id,
            reason_code=cls.reason_code,
        )
        cls.packet_with_properties = PubRecPacket(
            packet_id=cls.packet_id,
            reason_code=cls.reason_code,
            properties=cls.properties,
        )

    def test_pub_rec_packet_init_defaults(self) -> None:
        assert self.packet._packet_id == self.packet_id
        assert self.packet._reason_code == self.reason_code
        assert self.packet._properties == {}

    def test_pub_rec_packet_init_with_properties(self) -> None:
        assert self.packet_with_properties._packet_id == self.packet_id
        assert self.packet_with_properties._reason_code == self.reason_code
        assert self.packet_with_properties._properties == self.properties

    def test_pub_rec_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == self.reason_code.code

    def test_pub_rec_packet_to_bytes_with_properties(self) -> None:
        packet_bytes: bytearray = self.packet_with_properties.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet_with_properties.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == self.reason_code.code
        assert len(packet_body) > 3

    def test_pub_rec_packet_from_bytes_basic(self) -> None:
        reconstructed: PubRecPacket = cast(
            PubRecPacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._packet_id == self.packet._packet_id
        assert reconstructed._reason_code == self.packet._reason_code
        assert reconstructed._properties == self.packet._properties

    def test_pub_rec_packet_from_bytes_with_properties(self) -> None:
        reconstructed: PubRecPacket = cast(
            PubRecPacket, to_byte_reconstruct(self.packet_with_properties)
        )

        assert (
            reconstructed._packet_id == self.packet_with_properties._packet_id
        )
        assert (
            reconstructed._reason_code
            == self.packet_with_properties._reason_code
        )
        assert (
            reconstructed._properties
            == self.packet_with_properties._properties
        )

    def test_pub_rec_packet_invalid_reason_code(self) -> None:
        invalid_reason_code: int = 255
        packet_body: bytearray = bytearray()
        packet_body += TwoByteCodec.encode(123)  # packet id
        packet_body += OneByteCodec.encode(invalid_reason_code)
        packet_body += OneByteCodec.encode(0)

        with pytest.raises(KeyError):
            PubRecPacket.from_bytes(0x40, packet_body)


class TestPubRelPacket:
    packet_id: int
    reason_code: ReasonCode
    properties: DictStrObject

    packet: PubRelPacket
    packet_with_properties: PubRelPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.packet_id = 123
        cls.reason_code = SUCCESS
        cls.properties = {REASON_STRING.name: "value"}

        cls.packet = PubRelPacket(
            packet_id=cls.packet_id,
            reason_code=cls.reason_code,
        )
        cls.packet_with_properties = PubRelPacket(
            packet_id=cls.packet_id,
            reason_code=cls.reason_code,
            properties=cls.properties,
        )

    def test_pub_rel_packet_init_defaults(self) -> None:
        assert self.packet._packet_id == self.packet_id
        assert self.packet._reason_code == self.reason_code
        assert self.packet._properties == {}

    def test_pub_rel_packet_init_with_properties(self) -> None:
        assert self.packet_with_properties._packet_id == self.packet_id
        assert self.packet_with_properties._reason_code == self.reason_code
        assert self.packet_with_properties._properties == self.properties

    def test_pub_rel_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == ((self.packet.TYPE << 4) | 0b0010)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == self.reason_code.code

    def test_pub_rel_packet_to_bytes_with_properties(self) -> None:
        packet_bytes: bytearray = self.packet_with_properties.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == ((self.packet_with_properties.TYPE << 4) | 0b0010)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == self.reason_code.code
        assert len(packet_body) > 3

    def test_pub_rel_packet_from_bytes_basic(self) -> None:
        reconstructed: PubRelPacket = cast(
            PubRelPacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._packet_id == self.packet._packet_id
        assert reconstructed._reason_code == self.packet._reason_code
        assert reconstructed._properties == self.packet._properties

    def test_pub_rel_packet_from_bytes_with_properties(self) -> None:
        reconstructed: PubRelPacket = cast(
            PubRelPacket, to_byte_reconstruct(self.packet_with_properties)
        )

        assert (
            reconstructed._packet_id == self.packet_with_properties._packet_id
        )
        assert (
            reconstructed._reason_code
            == self.packet_with_properties._reason_code
        )
        assert (
            reconstructed._properties
            == self.packet_with_properties._properties
        )

    def test_pub_rel_packet_invalid_reason_code(self) -> None:
        invalid_reason_code: int = 255
        packet_body: bytearray = bytearray()
        packet_body += TwoByteCodec.encode(123)  # packet id
        packet_body += OneByteCodec.encode(invalid_reason_code)
        packet_body += OneByteCodec.encode(0)

        with pytest.raises(KeyError):
            PubRelPacket.from_bytes(0x40, packet_body)


class TestPubCompPacket:
    packet_id: int
    reason_code: ReasonCode
    properties: DictStrObject

    packet: PubCompPacket
    packet_with_properties: PubCompPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.packet_id = 123
        cls.reason_code = SUCCESS
        cls.properties = {REASON_STRING.name: "value"}

        cls.packet = PubCompPacket(
            packet_id=cls.packet_id,
            reason_code=cls.reason_code,
        )
        cls.packet_with_properties = PubCompPacket(
            packet_id=cls.packet_id,
            reason_code=cls.reason_code,
            properties=cls.properties,
        )

    def test_pub_comp_packet_init_defaults(self) -> None:
        assert self.packet._packet_id == self.packet_id
        assert self.packet._reason_code == self.reason_code
        assert self.packet._properties == {}

    def test_pub_comp_packet_init_with_properties(self) -> None:
        assert self.packet_with_properties._packet_id == self.packet_id
        assert self.packet_with_properties._reason_code == self.reason_code
        assert self.packet_with_properties._properties == self.properties

    def test_pub_comp_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == self.reason_code.code

    def test_pub_comp_packet_to_bytes_with_properties(self) -> None:
        packet_bytes: bytearray = self.packet_with_properties.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet_with_properties.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == self.reason_code.code
        assert len(packet_body) > 3

    def test_pub_comp_packet_from_bytes_basic(self) -> None:
        reconstructed: PubCompPacket = cast(
            PubCompPacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._packet_id == self.packet._packet_id
        assert reconstructed._reason_code == self.packet._reason_code
        assert reconstructed._properties == self.packet._properties

    def test_pub_comp_packet_from_bytes_with_properties(self) -> None:
        reconstructed: PubCompPacket = cast(
            PubCompPacket, to_byte_reconstruct(self.packet_with_properties)
        )

        assert (
            reconstructed._packet_id == self.packet_with_properties._packet_id
        )
        assert (
            reconstructed._reason_code
            == self.packet_with_properties._reason_code
        )
        assert (
            reconstructed._properties
            == self.packet_with_properties._properties
        )

    def test_pub_comp_packet_invalid_reason_code(self) -> None:
        invalid_reason_code: int = 255
        packet_body: bytearray = bytearray()
        packet_body += TwoByteCodec.encode(123)  # packet id
        packet_body += OneByteCodec.encode(invalid_reason_code)
        packet_body += OneByteCodec.encode(0)

        with pytest.raises(KeyError):
            PubCompPacket.from_bytes(0x40, packet_body)


class TestSubscribePacket:
    packet_id: int
    properties: DictStrObject
    subscription_one: Subscription
    subscription_two: Subscription

    topics_one: list[Subscription]
    topics_two: list[Subscription]

    packet: SubscribePacket
    packet_with_properties: SubscribePacket
    packet_multiple_topics: SubscribePacket
    packet_multiple_topics_properties: SubscribePacket

    @classmethod
    def setup_class(cls) -> None:
        cls.packet_id = 123
        cls.properties = {REASON_STRING.name: "value"}
        cls.subscription_one = Subscription(
            topic="test/topic-1",
            qos=1,
            no_local=False,
            retain_as_published=False,
            retain_handling=0,
        )
        cls.subscription_two = Subscription(
            topic="test/topic-2",
            qos=3,
            no_local=False,
            retain_as_published=True,
            retain_handling=0,
        )
        cls.topics_one = [cls.subscription_one]
        cls.topics_two = [cls.subscription_one, cls.subscription_two]

        cls.packet = SubscribePacket(
            packet_id=cls.packet_id,
            topics=cls.topics_one,
        )
        cls.packet_with_properties = SubscribePacket(
            packet_id=cls.packet_id,
            topics=cls.topics_one,
            properties=cls.properties,
        )
        cls.packet_multiple_topics = SubscribePacket(
            packet_id=cls.packet_id,
            topics=cls.topics_two,
        )
        cls.packet_multiple_topics_properties = SubscribePacket(
            packet_id=cls.packet_id,
            topics=cls.topics_two,
            properties=cls.properties,
        )

    def test_subscribe_packet_init_defaults(self) -> None:
        assert self.packet._packet_id == self.packet_id
        assert len(self.packet._topics) == len(self.topics_one)
        assert self.packet._topics[0]._topic == self.subscription_one._topic
        assert self.packet._topics[0]._qos == self.subscription_one._qos
        assert self.packet._properties == {}

    def test_subscribe_packet_init_with_properties(self) -> None:
        assert self.packet_with_properties._packet_id == self.packet_id
        assert len(self.packet_with_properties._topics) == len(self.topics_one)
        assert self.packet_with_properties._properties == self.properties

    def test_subscribe_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == ((self.packet.TYPE << 4) | 0b0010)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert len(packet_body) > 3

    def test_subscribe_packet_to_bytes_with_multiple_topics(self) -> None:
        packet_bytes: bytearray = self.packet_multiple_topics.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == ((self.packet.TYPE << 4) | 0b0010)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert len(packet_body) > 3

    def test_subscribe_packet_from_bytes_basic(self) -> None:
        reconstructed: SubscribePacket = cast(
            SubscribePacket, to_byte_reconstruct(self.packet)
        )
        assert reconstructed._packet_id == self.packet._packet_id
        assert len(reconstructed._topics) == len(self.packet._topics)
        assert reconstructed._topics[0]._topic == self.packet._topics[0]._topic
        assert reconstructed._topics[0]._qos == self.packet._topics[0]._qos

    def test_subscribe_packet_from_bytes_with_multiple_topics(self) -> None:
        reconstructed: SubscribePacket = cast(
            SubscribePacket, to_byte_reconstruct(self.packet_multiple_topics)
        )

        assert (
            reconstructed._packet_id == self.packet_multiple_topics._packet_id
        )
        assert len(reconstructed._topics) == len(
            self.packet_multiple_topics._topics
        )
        for i, topic in enumerate(self.packet_multiple_topics._topics):
            assert reconstructed._topics[i]._topic == topic._topic
            assert reconstructed._topics[i]._qos == topic._qos


class TestSubAckPacket:
    packet_id: int
    rc: ReasonCode
    reason_code: list[ReasonCode]
    reason_codes: list[ReasonCode]
    properties: DictStrObject

    packet: SubAckPacket
    packet_with_properties: SubAckPacket
    packet_with_multiple_reason_codes: SubAckPacket
    packet_with_multiple_reason_codes_properties: SubAckPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.packet_id = 123
        cls.rc = GRANTED_QOS_0
        cls.reason_code = [cls.rc]
        cls.reason_codes = [cls.rc, cls.rc]
        cls.properties = {REASON_STRING.name: "value"}

        cls.packet = SubAckPacket(
            packet_id=cls.packet_id,
            reason_codes=cls.reason_code,
        )
        cls.packet_with_properties = SubAckPacket(
            packet_id=cls.packet_id,
            reason_codes=cls.reason_code,
            properties=cls.properties,
        )
        cls.packet_with_multiple_reason_codes = SubAckPacket(
            packet_id=cls.packet_id,
            reason_codes=cls.reason_codes,
        )
        cls.packet_with_multiple_reason_codes_properties = SubAckPacket(
            packet_id=cls.packet_id,
            reason_codes=cls.reason_codes,
            properties=cls.properties,
        )

    def test_sub_ack_packet_init_defaults(self) -> None:
        assert self.packet._packet_id == self.packet_id
        assert len(self.packet._reason_codes) == 1
        assert self.packet._reason_codes[0] == self.rc
        assert self.packet._properties == {}

    def test_sub_ack_packet_init_with_properties(self) -> None:
        assert self.packet_with_properties._packet_id == self.packet_id
        assert len(self.packet_with_properties._reason_codes) == 1
        assert self.packet_with_properties._properties == self.properties

    def test_sub_ack_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == GRANTED_QOS_0.code

    def test_sub_ack_packet_to_bytes_with_multiple_reason_codes(self) -> None:
        packet_bytes: bytearray = (
            self.packet_with_multiple_reason_codes.to_bytes()
        )
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2:-1] == bytearray(
            [rc.code for rc in self.reason_codes]
        )

    def test_sub_ack_packet_to_bytes_with_properties(self) -> None:
        packet_bytes: bytearray = self.packet_with_properties.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert 2 < len(packet_body)

    def test_sub_ack_packet_from_bytes_basic(self) -> None:
        reconstructed: SubAckPacket = cast(
            SubAckPacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._packet_id == self.packet._packet_id
        assert reconstructed._reason_codes == self.packet._reason_codes
        assert reconstructed._properties == self.packet._properties

    def test_sub_ack_packet_from_bytes_with_multiple_reason_codes(
        self,
    ) -> None:
        reconstructed: SubAckPacket = cast(
            SubAckPacket,
            to_byte_reconstruct(self.packet_with_multiple_reason_codes),
        )

        assert (
            reconstructed._packet_id
            == self.packet_with_multiple_reason_codes._packet_id
        )
        assert (
            reconstructed._reason_codes
            == self.packet_with_multiple_reason_codes._reason_codes
        )
        assert (
            reconstructed._properties
            == self.packet_with_multiple_reason_codes._properties
        )


class TestUnSubscribePacket:
    packet_id: int
    topic_one: str
    topic_two: str
    topics: list[str]
    topics_multiple: list[str]
    properties: DictStrObject

    packet: UnSubscribePacket
    packet_with_properties: UnSubscribePacket
    packet_with_multiple_topics: UnSubscribePacket
    packet_with_multiple_topics_properties: UnSubscribePacket

    @classmethod
    def setup_class(cls) -> None:
        cls.packet_id = 1
        cls.topic_one = "topic/1"
        cls.topic_two = "topic/2"
        cls.topics = [cls.topic_one]
        cls.topics_multiple = [cls.topic_one, cls.topic_two]
        cls.properties = {USER_PROPERTY.name: ("apple", "one")}
        cls.packet = UnSubscribePacket(
            packet_id=cls.packet_id,
            topics=cls.topics,
        )
        cls.packet_with_properties = UnSubscribePacket(
            packet_id=cls.packet_id,
            topics=cls.topics,
            properties=cls.properties,
        )
        cls.packet_with_multiple_topics = UnSubscribePacket(
            packet_id=cls.packet_id,
            topics=cls.topics_multiple,
        )
        cls.packet_with_multiple_topics_properties = UnSubscribePacket(
            packet_id=cls.packet_id,
            topics=cls.topics_multiple,
            properties=cls.properties,
        )

    def test_unsubscribe_packet_init_defaults(self) -> None:
        assert self.packet._packet_id == self.packet_id
        assert len(self.packet._topics) == len(self.topics)
        assert self.packet._topics[0] == self.topic_one
        assert self.packet._properties == {}

    def test_unsubscribe_packet_init_with_properties(self) -> None:
        assert self.packet_with_properties._packet_id == 1
        assert len(self.packet_with_properties._topics) == 1
        assert self.packet_with_properties._topics[0] == self.topic_one
        assert self.packet_with_properties._properties == self.properties

    def test_unsubscribe_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == ((self.packet.TYPE << 4) | 0b0010)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == 0
        assert StrCodec.decode(packet_body[3:])[1] == "topic/1"

    def test_unsubscribe_packet_to_bytes_with_multiple_topics(self) -> None:
        packet_bytes: bytearray = self.packet_with_multiple_topics.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == ((self.packet.TYPE << 4) | 0b0010)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == 0
        decoded_topics: list[str] = []
        offset = 3
        for _ in self.topics_multiple:
            topic_len, topic = StrCodec.decode(packet_body[offset:])
            offset += topic_len
            decoded_topics.append(topic)
        assert decoded_topics == self.topics_multiple

    def test_unsubscribe_packet_to_bytes_with_properties(self) -> None:
        packet_bytes: bytearray = self.packet_with_properties.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == ((self.packet.TYPE << 4) | 0b0010)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert 2 < len(packet_body)

    def test_unsubscribe_packet_from_bytes_basic(self) -> None:
        reconstructed: UnSubscribePacket = cast(
            UnSubscribePacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._packet_id == self.packet._packet_id
        assert reconstructed._topics == self.packet._topics
        assert reconstructed._properties == self.packet._properties

    def test_unsubscribe_packet_from_bytes_with_multiple_topics(self) -> None:
        reconstructed: UnSubscribePacket = cast(
            UnSubscribePacket,
            to_byte_reconstruct(self.packet_with_multiple_topics),
        )

        assert (
            reconstructed._packet_id
            == self.packet_with_multiple_topics._packet_id
        )
        assert reconstructed._topics == tuple(
            self.packet_with_multiple_topics._topics
        )
        assert (
            reconstructed._properties
            == self.packet_with_multiple_topics._properties
        )

    def test_unsubscribe_packet_from_bytes_with_properties(self) -> None:
        reconstructed: UnSubscribePacket = cast(
            UnSubscribePacket, to_byte_reconstruct(self.packet_with_properties)
        )

        assert (
            reconstructed._packet_id == self.packet_with_properties._packet_id
        )
        assert reconstructed._topics == self.packet_with_properties._topics
        assert (
            reconstructed._properties
            == self.packet_with_properties._properties
        )


class TestUnSubAckPacket:
    packet_id: int
    rc: ReasonCode
    reason_code_one: list[ReasonCode]
    reason_code_two: list[ReasonCode]
    properties: DictStrObject

    packet: UnSubAckPacket
    packet_with_properties: UnSubAckPacket
    packet_with_multiple_rc: UnSubAckPacket
    packet_with_multiple_rc_properties: UnSubAckPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.packet_id = 1
        cls.rc = SUCCESS
        cls.reason_code_one = [cls.rc]
        cls.reason_code_two = [cls.rc, cls.rc]
        cls.properties = {USER_PROPERTY.name: ("apple", "one")}

        cls.packet = UnSubAckPacket(
            packet_id=cls.packet_id,
            reason_codes=cls.reason_code_one,
        )
        cls.packet_with_properties = UnSubAckPacket(
            packet_id=cls.packet_id,
            reason_codes=cls.reason_code_one,
            properties=cls.properties,
        )
        cls.packet_with_multiple_rc = UnSubAckPacket(
            packet_id=cls.packet_id,
            reason_codes=cls.reason_code_two,
        )
        cls.packet_with_multiple_rc_properties = UnSubAckPacket(
            packet_id=cls.packet_id,
            reason_codes=cls.reason_code_two,
            properties=cls.properties,
        )

    def test_unsub_ack_packet_init_defaults(self) -> None:
        assert self.packet._packet_id == self.packet_id
        assert len(self.packet._reason_codes) == len(self.reason_code_one)
        assert self.packet._reason_codes[0] == self.rc
        assert self.packet._properties == {}

    def test_unsub_ack_packet_init_with_properties(self) -> None:
        assert self.packet_with_properties._packet_id == self.packet_id
        assert len(self.packet_with_properties._reason_codes) == len(
            self.reason_code_one
        )
        assert self.packet_with_properties._properties == self.properties

    def test_unsub_ack_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == 0
        assert packet_body[3:] == bytearray([self.rc.code])

    def test_unsub_ack_packet_to_bytes_with_multiple_reason_codes(
        self,
    ) -> None:
        packet_bytes: bytearray = self.packet_with_multiple_rc.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert packet_body[2] == 0
        assert packet_body[3:] == bytearray(
            [rc.code for rc in self.reason_code_two]
        )

    def test_unsub_ack_packet_to_bytes_with_properties(self) -> None:
        packet_bytes: bytearray = self.packet_with_multiple_rc.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(self.packet_id)
        assert 2 < len(packet_body)

    def test_unsub_ack_packet_from_bytes_basic(self) -> None:
        reconstructed: UnSubAckPacket = cast(
            UnSubAckPacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._packet_id == self.packet._packet_id
        assert reconstructed._reason_codes == self.packet._reason_codes
        assert reconstructed._properties == self.packet._properties

    def test_unsub_ack_packet_from_bytes_with_multiple_reason_codes(
        self,
    ) -> None:
        reconstructed: UnSubAckPacket = cast(
            UnSubAckPacket, to_byte_reconstruct(self.packet_with_multiple_rc)
        )

        assert (
            reconstructed._packet_id == self.packet_with_multiple_rc._packet_id
        )
        assert reconstructed._reason_codes == tuple(self.reason_code_two)
        assert (
            reconstructed._properties
            == self.packet_with_multiple_rc._properties
        )


class TestPingReqPacket:
    packet: PingReqPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.packet = PingReqPacket()

    def test_ping_req_packet_to_bytes(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)

    def test_ping_req_packet_from_bytes(self) -> None:
        reconstructed: PingReqPacket = cast(
            PingReqPacket, to_byte_reconstruct(self.packet)
        )
        assert isinstance(reconstructed, PingReqPacket)


class TestPingRespPacket:
    packet: PingRespPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.packet = PingRespPacket()

    def test_ping_resp_packet_to_bytes(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)

    def test_ping_resp_packet_from_bytes(self) -> None:
        reconstructed: PingRespPacket = cast(
            PingRespPacket, to_byte_reconstruct(self.packet)
        )
        assert isinstance(reconstructed, PingRespPacket)


class TestDisconnectPacket:
    rc: ReasonCode
    properties: DictStrObject

    packet: DisconnectPacket
    packet_with_properties: DisconnectPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.rc = NORMAL_DISCONNECTION
        cls.properties = {USER_PROPERTY.name: ("apple", "one")}

        cls.packet = DisconnectPacket(reason_code=cls.rc)
        cls.packet_with_properties = DisconnectPacket(
            reason_code=cls.rc,
            properties=cls.properties,
        )

    def test_disconnect_packet_init_defaults(self) -> None:
        assert self.packet._reason_code == self.rc
        assert self.packet._properties == {}

    def test_disconnect_packet_init_with_properties(self) -> None:
        assert self.packet_with_properties._reason_code == self.rc
        assert self.packet_with_properties._properties == self.properties

    def test_disconnect_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0] == self.rc.code

    def test_disconnect_packet_to_bytes_with_properties(self) -> None:
        packet_bytes: bytearray = self.packet_with_properties.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0] == self.rc.code
        assert 1 < len(packet_body)

    def test_disconnect_packet_from_bytes_basic(self) -> None:
        reconstructed: DisconnectPacket = cast(
            DisconnectPacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._reason_code == self.packet._reason_code
        assert reconstructed._properties == self.packet._properties

    def test_disconnect_packet_from_bytes_with_properties(self) -> None:
        reconstructed: DisconnectPacket = cast(
            DisconnectPacket, to_byte_reconstruct(self.packet_with_properties)
        )

        assert (
            reconstructed._reason_code
            == self.packet_with_properties._reason_code
        )
        assert (
            reconstructed._properties
            == self.packet_with_properties._properties
        )


class TestAuthPacket:
    rc: ReasonCode
    properties: DictStrObject

    packet: AuthPacket
    packet_with_properties: AuthPacket

    @classmethod
    def setup_class(cls) -> None:
        cls.rc = SUCCESS
        cls.properties = {USER_PROPERTY.name: ("apple", "one")}

        cls.packet = AuthPacket(reason_code=cls.rc)
        cls.packet_with_properties = AuthPacket(
            reason_code=cls.rc,
            properties=cls.properties,
        )

    def test_auth_packet_init_defaults(self) -> None:
        assert self.packet._reason_code == self.rc
        assert self.packet._properties == {}

    def test_auth_packet_init_with_properties(self) -> None:
        assert self.packet_with_properties._reason_code == self.rc
        assert self.packet_with_properties._properties == self.properties

    def test_auth_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0] == self.rc.code

    def test_auth_packet_to_bytes_with_properties(self) -> None:
        packet_bytes: bytearray = self.packet_with_properties.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (self.packet.TYPE << 4)
        assert packet_body[0] == self.rc.code
        assert 1 < len(packet_body)

    def test_auth_packet_from_bytes_basic(self) -> None:
        reconstructed: AuthPacket = cast(
            AuthPacket, to_byte_reconstruct(self.packet)
        )

        assert reconstructed._reason_code == self.packet._reason_code
        assert reconstructed._properties == self.packet._properties

    def test_auth_packet_from_bytes_with_properties(self) -> None:
        reconstructed: AuthPacket = cast(
            AuthPacket, to_byte_reconstruct(self.packet_with_properties)
        )

        assert (
            reconstructed._reason_code
            == self.packet_with_properties._reason_code
        )
        assert (
            reconstructed._properties
            == self.packet_with_properties._properties
        )
