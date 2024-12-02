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
    def test_packet_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            Packet()  # type: ignore[abstract]

    def test_from_bytes_is_abstract(self) -> None:
        fixed_byte: int = 0x00
        packet_body: bytearray = bytearray()
        with pytest.raises(NotImplementedError):
            Packet.from_bytes(fixed_byte=fixed_byte, packet_body=packet_body)

    def test_to_bytes_is_abstract(self, mocker: MockFixture) -> None:
        with pytest.raises(NotImplementedError):
            Packet.to_bytes(mocker)  # type: ignore[arg-type]

    def test_remaining_length_empty(self) -> None:
        result = Packet._remaining_length()
        expected = VariableByteCodec.encode(0)
        assert result == expected

    def test_remaining_length_variable_header_only(self) -> None:
        variable_header = b"header"
        result = Packet._remaining_length(variable_header=variable_header)
        expected = VariableByteCodec.encode(len(variable_header))
        assert result == expected

    def test_remaining_length_payload_only(self) -> None:
        payload = b"payload"
        result = Packet._remaining_length(payload=payload)
        expected = VariableByteCodec.encode(len(payload))
        assert result == expected

    def test_remaining_length_combined(self) -> None:
        variable_header = b"header"
        payload = b"payload"
        result = Packet._remaining_length(
            variable_header=variable_header, payload=payload
        )
        expected = VariableByteCodec.encode(
            len(variable_header) + len(payload)
        )
        assert result == expected

    def test_fixed_header_empty(self) -> None:
        first_byte = 0x10
        result = Packet._fixed_header(first_byte=first_byte)
        expected = bytearray([first_byte])
        expected += VariableByteCodec.encode(0)
        assert result == expected

    def test_to_packet_empty(self) -> None:
        first_byte = 0x10
        result = Packet._to_packet(first_byte)
        expected_fixed_header = Packet._fixed_header(first_byte)
        assert result == expected_fixed_header

    def test_fixed_header_basic(self) -> None:
        first_byte = 0x10
        variable_header = b"header"
        payload = b"payload"
        result = Packet._fixed_header(first_byte, variable_header, payload)
        expected_length = VariableByteCodec.encode(
            len(variable_header) + len(payload)
        )

        assert result[0] == first_byte
        assert result[1:] == expected_length

    def test_to_packet_with_variable_header(self) -> None:
        first_byte = 0x10
        variable_header = b"header"
        result = Packet._to_packet(first_byte, variable_header=variable_header)
        expected_fixed_header = Packet._fixed_header(
            first_byte, variable_header=variable_header
        )
        expected_packet = expected_fixed_header + variable_header
        assert result == expected_packet

    def test_to_packet_with_payload(self) -> None:
        first_byte = 0x10
        payload = b"payload"
        result = Packet._to_packet(first_byte, payload=payload)
        expected_fixed_header = Packet._fixed_header(
            first_byte, payload=payload
        )
        expected_packet = expected_fixed_header + payload
        assert result == expected_packet

    def test_to_packet_with_variable_header_and_payload(self) -> None:
        first_byte = 0x10
        variable_header = b"header"
        payload = b"payload"
        result = Packet._to_packet(
            first_byte, variable_header=variable_header, payload=payload
        )
        expected_fixed_header = Packet._fixed_header(
            first_byte, variable_header=variable_header, payload=payload
        )
        expected_packet = expected_fixed_header + variable_header + payload
        assert result == expected_packet


class TestConnectPacket:
    connect_flags_i: int

    def setup_method(self) -> None:
        self.client_id: str = "test"
        self.default_packet: ConnectPacket = ConnectPacket(
            client_id=self.client_id
        )
        self.flags_i: int = 9

    def test_connect_packet_is_subclass_of_packet(self) -> None:
        assert issubclass(ConnectPacket, Packet)

    def test_connect_packet_init_default(self) -> None:
        assert self.default_packet._client_id == self.client_id
        assert self.default_packet._clean_start is True
        assert self.default_packet._username is None
        assert self.default_packet._password is None
        assert self.default_packet._keep_alive == 60
        assert self.default_packet._properties == {}
        assert self.default_packet._will_message is None

    def test_connect_packet_init_with_property(self) -> None:
        properties: DictStrObject = {}
        connect_packet: ConnectPacket = ConnectPacket(
            client_id=self.client_id, properties=properties
        )
        assert connect_packet._client_id == self.client_id
        assert connect_packet._clean_start is True
        assert connect_packet._username is None
        assert connect_packet._password is None
        assert connect_packet._keep_alive == 60
        assert connect_packet._properties == {}
        assert connect_packet._will_message is None

    def test_connect_packet_custom_init(self) -> None:
        client_id: str = "test_client"
        username: str = "user"
        password: str = "pass"
        properties: DictStrObject = {"test_property": "test_value"}
        will_message: WillMessage = WillMessage(
            topic="topic",
            message="message",
            qos=1,
            retain=True,
            properties={},
        )
        connect_packet: ConnectPacket = ConnectPacket(
            client_id=client_id,
            clean_start=False,
            username=username,
            password=password,
            keep_alive=30,
            properties=properties,
            will_message=will_message,
        )

        assert connect_packet._client_id == client_id
        assert connect_packet._clean_start is False
        assert connect_packet._username == username
        assert connect_packet._password == password
        assert connect_packet._keep_alive == 30
        assert connect_packet._properties == properties
        assert connect_packet._will_message == will_message

    def test_connect_packet_to_bytes_basic(self) -> None:
        client_id = "test_client"
        connect_packet = ConnectPacket(client_id=client_id)

        result = connect_packet.to_bytes()
        assert isinstance(result, bytearray)

    def test_connect_packet_to_bytes_with_clean_start(self) -> None:
        client_id = "test_client"
        connect_packet = ConnectPacket(client_id=client_id, clean_start=True)

        result = connect_packet.to_bytes()
        assert result[self.flags_i] & 0b00000010 != 0

    def test_connect_packet_to_bytes_with_username_password(self) -> None:
        client_id = "test_client"
        username = "user"
        password = "pass"
        connect_packet = ConnectPacket(
            client_id=client_id, username=username, password=password
        )

        result = connect_packet.to_bytes()
        assert result[self.flags_i] & 0b10000000 != 0
        assert result[self.flags_i] & 0b01000000 != 0

    def test_connect_packet_to_bytes_with_will_message(self) -> None:
        client_id = "test_client"
        will_message = WillMessage(
            topic="test_topic",
            message="test_message",
            qos=1,
            retain=True,
            properties={CONTENT_TYPE.name: "test_value"},
        )
        connect_packet = ConnectPacket(
            client_id=client_id, will_message=will_message
        )

        result = connect_packet.to_bytes()
        assert result[self.flags_i] & 0b00000100 != 0
        assert result[self.flags_i] & 0b00100000 != 0

    def test_connect_packet_from_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.default_packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        reconstructed: ConnectPacket = ConnectPacket.from_bytes(
            first_byte, packet_body
        )

        assert reconstructed._client_id == self.client_id

    def test_connect_packet_from_bytes_with_username_password(self) -> None:
        client_id = "test_client"
        username = "user"
        password = "pass"
        connect_packet = ConnectPacket(
            client_id=client_id, username=username, password=password
        )
        packet_bytes = connect_packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        reconstructed: ConnectPacket = ConnectPacket.from_bytes(
            first_byte, packet_body
        )
        assert reconstructed._username == username
        assert reconstructed._password == password

    def test_connect_packet_from_bytes_with_will_message(self) -> None:
        client_id = "test_client"
        will_message = WillMessage(
            topic="test_topic",
            message="test_message",
            qos=1,
            retain=True,
            properties={CONTENT_TYPE.name: "test_value"},
        )
        connect_packet = ConnectPacket(
            client_id=client_id, will_message=will_message
        )
        packet_bytes = connect_packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        reconstructed: ConnectPacket = ConnectPacket.from_bytes(
            first_byte, packet_body
        )
        reconstructed_will_message: WillMessage = cast(
            WillMessage, reconstructed._will_message
        )
        assert reconstructed_will_message.topic == will_message.topic
        assert reconstructed_will_message.message == will_message.message
        assert reconstructed_will_message.qos == will_message.qos
        assert reconstructed_will_message.retain == will_message.retain
        assert reconstructed_will_message.properties == will_message.properties


class TestConnAckPacket:
    def setup_method(self) -> None:
        self.session_present: bool = False
        self.reason_code: ReasonCode = SUCCESS
        self.properties: DictStrObject = {MAX_QOS.name: 2}
        self.default_packet: ConnAckPacket = ConnAckPacket(
            session_present=self.session_present,
            reason_code=self.reason_code,
        )

    def test_conn_ack_packet_defaults(self) -> None:
        assert self.default_packet._session_present is False
        assert self.default_packet._reason_code == SUCCESS
        assert self.default_packet._properties == {}

    def test_conn_ack_packet_with_properties_init(self) -> None:
        packet: ConnAckPacket = ConnAckPacket(
            session_present=self.session_present,
            reason_code=self.reason_code,
            properties={},
        )
        assert packet._session_present is False
        assert packet._reason_code == SUCCESS
        assert packet._properties == {}

    def test_conn_ack_packet_to_bytes_basic(self) -> None:
        packet = ConnAckPacket(
            session_present=True, reason_code=self.reason_code
        )
        packet_bytes = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (packet.TYPE << 4)
        assert packet_body[0] == 0b00000001
        assert packet_body[1] == self.reason_code.code

    def test_conn_ack_packet_with_properties(self) -> None:
        packet = ConnAckPacket(
            session_present=False,
            reason_code=self.reason_code,
            properties=self.properties,
        )

        packet_bytes = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (packet.TYPE << 4)
        assert packet_body[0] == 0b00000000
        assert packet_body[1] == self.reason_code.code
        assert len(packet_body) > 2

    def test_conn_ack_packet_basic(self) -> None:
        packet = ConnAckPacket(
            session_present=True,
            reason_code=self.reason_code,
            properties=self.properties,
        )

        packet_bytes = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)
        reconstructed = ConnAckPacket.from_bytes(first_byte, packet_body)
        assert reconstructed._session_present == packet._session_present
        assert reconstructed._reason_code == packet._reason_code
        assert reconstructed._properties == packet._properties


class TestPublishPacket:
    def test_publish_packet_defaults(self) -> None:
        packet: PublishPacket = PublishPacket(dup=False, qos=0, retain=False)
        assert packet._dup is False
        assert packet._qos == 0
        assert packet._retain is False
        assert packet._topic is None
        assert packet._packet_id is None
        assert packet._properties == {}
        assert packet._payload == b""

    def test_publish_packet_init_with_values(self) -> None:
        properties: DictStrObject = {CONTENT_TYPE.name: "value"}
        payload: bytes = b"test_payload"
        packet: PublishPacket = PublishPacket(
            dup=True,
            qos=1,
            retain=True,
            topic="test/topic",
            packet_id=123,
            properties=properties,
            payload=payload,
        )
        assert packet._dup is True
        assert packet._qos == 1
        assert packet._retain is True
        assert packet._topic == "test/topic"
        assert packet._packet_id == 123
        assert packet._properties == properties
        assert packet._payload == payload

    def test_publish_packet_invalid_qos(self) -> None:
        with pytest.raises(ValueError):
            PublishPacket(dup=False, qos=100, retain=False)

    def test_publish_packet_basic(self) -> None:
        packet = PublishPacket(
            dup=False, qos=0, retain=False, topic="test/topic", payload=b"data"
        )
        result = packet.to_bytes()
        assert isinstance(result, bytearray)
        assert result[0] == (packet.TYPE << 4)

    def test_publish_packet_with_qos(self) -> None:
        packet = PublishPacket(
            dup=True,
            qos=1,
            retain=True,
            topic="test/topic",
            packet_id=123,
            payload=b"data",
        )
        packet_bytes = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)
        assert isinstance(packet_bytes, bytearray)
        assert first_byte & 0b00001000 != 0
        assert first_byte & 0b00000110 != 0

    def test_publish_packet_without_packet_id(self) -> None:
        packet = PublishPacket(
            dup=False, qos=1, retain=False, topic="test/topic"
        )
        with pytest.raises(ValueError):
            packet.to_bytes()

    def test_publish_packet_from_bytes_basic(self) -> None:
        packet = PublishPacket(
            dup=False, qos=0, retain=False, topic="test/topic", payload=b"data"
        )

        packet_bytes = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)
        reconstructed = PublishPacket.from_bytes(first_byte, packet_body)

        assert reconstructed._dup == packet._dup
        assert reconstructed._qos == packet._qos
        assert reconstructed._retain == packet._retain
        assert reconstructed._topic == packet._topic
        assert reconstructed._payload == packet._payload

    def test_publish_packet_from_bytes_with_qos(self) -> None:
        packet: PublishPacket = PublishPacket(
            dup=True,
            qos=2,
            retain=True,
            topic="test/topic",
            packet_id=321,
            payload=b"test",
        )
        packet_bytes = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)
        reconstructed = PublishPacket.from_bytes(first_byte, packet_body)
        assert reconstructed._dup == packet._dup
        assert reconstructed._qos == packet._qos
        assert reconstructed._retain == packet._retain
        assert reconstructed._topic == packet._topic
        assert reconstructed._packet_id == packet._packet_id
        assert reconstructed._payload == packet._payload

    def test_publish_packet_from_bytes_with_properties(self) -> None:
        properties: DictStrObject = {CONTENT_TYPE.name: "value"}
        packet: PublishPacket = PublishPacket(
            dup=False,
            qos=1,
            retain=True,
            topic="test/topic",
            packet_id=45,
            properties=properties,
        )
        packet_bytes = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)
        reconstructed = PublishPacket.from_bytes(first_byte, packet_body)
        assert reconstructed._dup == packet._dup
        assert reconstructed._qos == packet._qos
        assert reconstructed._retain == packet._retain
        assert reconstructed._topic == packet._topic
        assert reconstructed._packet_id == packet._packet_id
        assert reconstructed._properties == packet._properties


class TestPubAckPacket:
    def test_pub_ack_packet_init_defaults(self) -> None:
        packet: PubAckPacket = PubAckPacket(packet_id=1, reason_code=SUCCESS)
        assert packet._packet_id == 1
        assert packet._reason_code == SUCCESS
        assert packet._properties == {}

    def test_pub_ack_packet_init_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubAckPacket = PubAckPacket(
            packet_id=123, reason_code=SUCCESS, properties=properties
        )
        assert packet._packet_id == 123
        assert packet._reason_code == SUCCESS
        assert packet._properties == properties

    def test_pub_ack_packet_to_bytes_basic(self) -> None:
        packet: PubAckPacket = PubAckPacket(packet_id=321, reason_code=SUCCESS)
        packet_bytes = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(321)
        assert packet_body[2] == SUCCESS.code

    def test_pub_ack_packet_to_bytes_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubAckPacket = PubAckPacket(
            packet_id=123, reason_code=SUCCESS, properties=properties
        )
        packet_bytes = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(123)
        assert packet_body[2] == SUCCESS.code
        assert len(packet_body) > 3

    def test_pub_ack_packet_from_bytes_basic(self) -> None:
        packet: PubAckPacket = PubAckPacket(packet_id=123, reason_code=SUCCESS)
        reconstructed: PubAckPacket = cast(
            PubAckPacket, to_byte_reconstruct(packet)
        )

        assert reconstructed._packet_id == packet._packet_id
        assert reconstructed._reason_code == packet._reason_code
        assert reconstructed._properties == packet._properties

    def test_pub_ack_packet_from_bytes_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubAckPacket = PubAckPacket(
            packet_id=45, reason_code=SUCCESS, properties=properties
        )
        reconstructed: PubAckPacket = cast(
            PubAckPacket, to_byte_reconstruct(packet)
        )
        assert reconstructed._packet_id == packet._packet_id
        assert reconstructed._reason_code == packet._reason_code
        assert reconstructed._properties == packet._properties

    def test_pub_ack_packet_invalid_reason_code(self) -> None:
        invalid_reason_code = 255
        packet_body: bytearray = bytearray()
        packet_body += TwoByteCodec.encode(123)  # packet id
        packet_body += OneByteCodec.encode(invalid_reason_code)
        packet_body += OneByteCodec.encode(0)

        with pytest.raises(KeyError):
            PubAckPacket.from_bytes(0x40, packet_body)


class TestPubRecPacket:
    def test_pub_rec_packet_init_defaults(self) -> None:
        packet: PubRecPacket = PubRecPacket(packet_id=1, reason_code=SUCCESS)
        assert packet._packet_id == 1
        assert packet._reason_code == SUCCESS
        assert packet._properties == {}

    def test_pub_rec_packet_init_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubRecPacket = PubRecPacket(
            packet_id=123, reason_code=SUCCESS, properties=properties
        )
        assert packet._packet_id == 123
        assert packet._reason_code == SUCCESS
        assert packet._properties == properties

    def test_pub_rec_packet_to_bytes_basic(self) -> None:
        packet: PubRecPacket = PubRecPacket(packet_id=321, reason_code=SUCCESS)
        packet_bytes: bytearray = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(321)
        assert packet_body[2] == SUCCESS.code

    def test_pub_rec_packet_to_bytes_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubRecPacket = PubRecPacket(
            packet_id=123, reason_code=SUCCESS, properties=properties
        )
        packet_bytes: bytearray = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(123)
        assert packet_body[2] == SUCCESS.code
        assert len(packet_body) > 3

    def test_pub_rec_packet_from_bytes_basic(self) -> None:
        packet: PubRecPacket = PubRecPacket(packet_id=123, reason_code=SUCCESS)
        reconstructed: PubRecPacket = cast(
            PubRecPacket, to_byte_reconstruct(packet)
        )

        assert reconstructed._packet_id == packet._packet_id
        assert reconstructed._reason_code == packet._reason_code
        assert reconstructed._properties == packet._properties

    def test_pub_rec_packet_from_bytes_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubRecPacket = PubRecPacket(
            packet_id=45, reason_code=SUCCESS, properties=properties
        )
        reconstructed: PubRecPacket = cast(
            PubRecPacket, to_byte_reconstruct(packet)
        )

        assert reconstructed._packet_id == packet._packet_id
        assert reconstructed._reason_code == packet._reason_code
        assert reconstructed._properties == packet._properties

    def test_pub_rec_packet_invalid_reason_code(self) -> None:
        invalid_reason_code: int = 255
        packet_body: bytearray = bytearray()
        packet_body += TwoByteCodec.encode(123)  # packet id
        packet_body += OneByteCodec.encode(invalid_reason_code)
        packet_body += OneByteCodec.encode(0)

        with pytest.raises(KeyError):
            PubRecPacket.from_bytes(0x40, packet_body)


class TestPubRelPacket:
    def test_pub_rel_packet_init_defaults(self) -> None:
        packet: PubRelPacket = PubRelPacket(packet_id=1, reason_code=SUCCESS)
        assert packet._packet_id == 1
        assert packet._reason_code == SUCCESS
        assert packet._properties == {}

    def test_pub_rel_packet_init_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubRelPacket = PubRelPacket(
            packet_id=123, reason_code=SUCCESS, properties=properties
        )
        assert packet._packet_id == 123
        assert packet._reason_code == SUCCESS
        assert packet._properties == properties

    def test_pub_rel_packet_to_bytes_basic(self) -> None:
        packet: PubRelPacket = PubRelPacket(packet_id=321, reason_code=SUCCESS)
        packet_bytes: bytearray = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == ((packet.TYPE << 4) | 0b0010)
        assert packet_body[0:2] == TwoByteCodec.encode(321)
        assert packet_body[2] == SUCCESS.code

    def test_pub_rel_packet_to_bytes_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubRelPacket = PubRelPacket(
            packet_id=123, reason_code=SUCCESS, properties=properties
        )
        packet_bytes: bytearray = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == ((packet.TYPE << 4) | 0b0010)
        assert packet_body[0:2] == TwoByteCodec.encode(123)
        assert packet_body[2] == SUCCESS.code
        assert len(packet_body) > 3

    def test_pub_rel_packet_from_bytes_basic(self) -> None:
        packet: PubRelPacket = PubRelPacket(packet_id=123, reason_code=SUCCESS)
        reconstructed: PubRelPacket = cast(
            PubRelPacket, to_byte_reconstruct(packet)
        )

        assert reconstructed._packet_id == packet._packet_id
        assert reconstructed._reason_code == packet._reason_code
        assert reconstructed._properties == packet._properties

    def test_pub_rel_packet_from_bytes_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubRelPacket = PubRelPacket(
            packet_id=45, reason_code=SUCCESS, properties=properties
        )
        reconstructed: PubRelPacket = cast(
            PubRelPacket, to_byte_reconstruct(packet)
        )

        assert reconstructed._packet_id == packet._packet_id
        assert reconstructed._reason_code == packet._reason_code
        assert reconstructed._properties == packet._properties

    def test_pub_rel_packet_invalid_reason_code(self) -> None:
        invalid_reason_code: int = 255
        packet_body: bytearray = bytearray()
        packet_body += TwoByteCodec.encode(123)  # packet id
        packet_body += OneByteCodec.encode(invalid_reason_code)
        packet_body += OneByteCodec.encode(0)

        with pytest.raises(KeyError):
            PubRelPacket.from_bytes(0x40, packet_body)


class TestPubCompPacket:
    def test_pub_comp_packet_init_defaults(self) -> None:
        packet: PubCompPacket = PubCompPacket(packet_id=1, reason_code=SUCCESS)
        assert packet._packet_id == 1
        assert packet._reason_code == SUCCESS
        assert packet._properties == {}

    def test_pub_comp_packet_init_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubCompPacket = PubCompPacket(
            packet_id=123, reason_code=SUCCESS, properties=properties
        )
        assert packet._packet_id == 123
        assert packet._reason_code == SUCCESS
        assert packet._properties == properties

    def test_pub_comp_packet_to_bytes_basic(self) -> None:
        packet: PubCompPacket = PubCompPacket(
            packet_id=321, reason_code=SUCCESS
        )
        packet_bytes: bytearray = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(321)
        assert packet_body[2] == SUCCESS.code

    def test_pub_comp_packet_to_bytes_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubCompPacket = PubCompPacket(
            packet_id=123, reason_code=SUCCESS, properties=properties
        )
        packet_bytes: bytearray = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == (packet.TYPE << 4)
        assert packet_body[0:2] == TwoByteCodec.encode(123)
        assert packet_body[2] == SUCCESS.code
        assert len(packet_body) > 3

    def test_pub_comp_packet_from_bytes_basic(self) -> None:
        packet: PubCompPacket = PubCompPacket(
            packet_id=123, reason_code=SUCCESS
        )
        reconstructed: PubCompPacket = cast(
            PubCompPacket, to_byte_reconstruct(packet)
        )

        assert reconstructed._packet_id == packet._packet_id
        assert reconstructed._reason_code == packet._reason_code
        assert reconstructed._properties == packet._properties

    def test_pub_comp_packet_from_bytes_with_properties(self) -> None:
        properties: DictStrObject = {REASON_STRING.name: "value"}
        packet: PubCompPacket = PubCompPacket(
            packet_id=45, reason_code=SUCCESS, properties=properties
        )
        reconstructed: PubCompPacket = cast(
            PubCompPacket, to_byte_reconstruct(packet)
        )

        assert reconstructed._packet_id == packet._packet_id
        assert reconstructed._reason_code == packet._reason_code
        assert reconstructed._properties == packet._properties

    def test_pub_comp_packet_invalid_reason_code(self) -> None:
        invalid_reason_code: int = 255
        packet_body: bytearray = bytearray()
        packet_body += TwoByteCodec.encode(123)  # packet id
        packet_body += OneByteCodec.encode(invalid_reason_code)
        packet_body += OneByteCodec.encode(0)

        with pytest.raises(KeyError):
            PubCompPacket.from_bytes(0x40, packet_body)


class TestSubscribePacket:
    def setup_method(self) -> None:
        self.subscription: Subscription = Subscription(
            topic="test/topic",
            qos=1,
            no_local=False,
            retain_as_published=False,
            retain_handling=0,
        )
        self.properties: DictStrObject = {REASON_STRING.name: "value"}
        self.packet: SubscribePacket = SubscribePacket(
            packet_id=1, topics=[self.subscription]
        )
        self.packet_with_properties: SubscribePacket = SubscribePacket(
            packet_id=1, topics=[self.subscription], properties=self.properties
        )

    def test_subscribe_packet_init_defaults(self) -> None:
        assert self.packet._packet_id == 1
        assert len(self.packet._topics) == 1
        assert self.packet._topics[0]._topic == "test/topic"
        assert self.packet._topics[0]._qos == 1
        assert self.packet._properties == {}

    def test_subscribe_packet_init_with_properties(self) -> None:
        assert self.packet_with_properties._packet_id == 1
        assert len(self.packet_with_properties._topics) == 1
        assert self.packet_with_properties._properties == self.properties

    def test_subscribe_packet_to_bytes_basic(self) -> None:
        packet_bytes: bytearray = self.packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)

        assert isinstance(packet_bytes, bytearray)
        assert first_byte == ((self.packet.TYPE << 4) | 0b0010)
        assert packet_body[0:2] == TwoByteCodec.encode(1)
        assert len(packet_body) > 3

    def test_subscribe_packet_to_bytes_with_multiple_topics(self) -> None:
        subscriptions: list[Subscription] = [
            Subscription(
                topic="topic/1",
                qos=1,
                no_local=False,
                retain_as_published=False,
                retain_handling=0,
            ),
            Subscription(
                topic="topic/2",
                qos=2,
                no_local=True,
                retain_as_published=True,
                retain_handling=1,
            ),
        ]
        packet = SubscribePacket(packet_id=123, topics=subscriptions)
        packet_bytes: bytearray = packet.to_bytes()
        first_byte, packet_body = to_decode(packet_bytes)
        assert isinstance(packet_bytes, bytearray)
        assert first_byte == ((self.packet.TYPE << 4) | 0b0010)
        assert packet_body[0:2] == TwoByteCodec.encode(123)
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
        subscriptions: list[Subscription] = [
            Subscription(
                topic="topic/1",
                qos=1,
                no_local=False,
                retain_as_published=False,
                retain_handling=0,
            ),
            Subscription(
                topic="topic/2",
                qos=2,
                no_local=True,
                retain_as_published=True,
                retain_handling=1,
            ),
        ]
        packet = SubscribePacket(packet_id=123, topics=subscriptions)
        reconstructed: SubscribePacket = cast(
            SubscribePacket, to_byte_reconstruct(packet)
        )
        assert reconstructed._packet_id == packet._packet_id
        assert len(reconstructed._topics) == len(packet._topics)
        for i, topic in enumerate(packet._topics):
            assert reconstructed._topics[i]._topic == topic._topic
            assert reconstructed._topics[i]._qos == topic._qos


class TestSubAckPacket:
    def setup_method(self) -> None:
        self.packet_id: int = 1
        self.rc: ReasonCode = GRANTED_QOS_0
        self.reason_code: list[ReasonCode] = [self.rc]
        self.reason_codes: list[ReasonCode] = [self.rc, self.rc]
        self.properties: DictStrObject = {REASON_STRING.name: "value"}
        self.packet: SubAckPacket = SubAckPacket(
            packet_id=self.packet_id,
            reason_codes=self.reason_code,
        )
        self.packet_with_properties: SubAckPacket = SubAckPacket(
            packet_id=self.packet_id,
            reason_codes=self.reason_code,
            properties=self.properties,
        )
        self.packet_with_multiple_reason_codes: SubAckPacket = SubAckPacket(
            packet_id=self.packet_id,
            reason_codes=self.reason_codes,
        )
        self.packet_with_multiple_reason_codes_properties: SubAckPacket = (
            SubAckPacket(
                packet_id=self.packet_id,
                reason_codes=self.reason_codes,
                properties=self.properties,
            )
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


"""
def test_disconnect_packet_(self) -> None:
"""


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
