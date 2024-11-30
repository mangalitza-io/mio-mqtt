import pytest

from mio_mqtt.packet.codec import Codec, DecodeError, EncodeError
from mio_mqtt.packet.properties import (
    PAYLOAD_FORMAT_ID,
    Property,
    PropertyCodec,
)
from mio_mqtt.types import Length


class MockCodec(Codec):
    @classmethod
    def encode(cls, __data: object) -> bytearray:
        if not isinstance(__data, int):
            raise EncodeError()
        return bytearray([__data])

    @classmethod
    def decode(cls, __bytearray: bytearray) -> tuple[Length, object]:
        if len(__bytearray) == 0:
            raise DecodeError()
        return 1, __bytearray[0]


class TestProperty:
    def setup_method(self) -> None:
        self.mock_codec = MockCodec
        self.test_property = Property(
            identifier=0x01, name="test_property", codec=self.mock_codec
        )

    def test_encode_valid_data(self) -> None:
        result = self.test_property.encode(42)
        assert result == bytearray([0x01, 42])

    def test_encode_invalid_data_raises_error(self) -> None:
        with pytest.raises(EncodeError):
            self.test_property.encode("invalid")

    def test_decode_valid_data(self) -> None:
        result = self.test_property.decode(bytearray([0x01, 42]))
        assert result == (2, 42)

    def test_decode_invalid_identifier_raises_error(self) -> None:
        with pytest.raises(TypeError):
            self.test_property.decode(bytearray([0x02, 42]))

    def test_decode_empty_data_raises_error(self) -> None:
        with pytest.raises(IndexError):
            self.test_property.decode(bytearray([]))

    def test_decode_invalid_data_raises_error(self) -> None:
        with pytest.raises(DecodeError):
            self.test_property.decode(bytearray([0x01]))


class TestPropertyCodec:
    def setup_method(self) -> None:
        self.mock_codec = MockCodec
        self.test_property1 = Property(
            identifier=0x01, name="test_property1", codec=self.mock_codec
        )
        self.test_property2 = Property(
            identifier=0x02, name="test_property2", codec=self.mock_codec
        )
        self.codec = PropertyCodec([self.test_property1, self.test_property2])

    def test_encode_by_id_valid(self) -> None:
        result = self.codec.encode_by_id({0x01: 42, 0x02: 84})
        assert result == (4, bytearray([0x01, 42, 0x02, 84]))

    def test_encode_by_id_invalid_id_raises_error(self) -> None:
        with pytest.raises(KeyError):
            self.codec.encode_by_id({0x03: 42})

    def test_encode_by_id_invalid_data_raises_error(self) -> None:
        with pytest.raises(EncodeError):
            self.codec.encode_by_id({0x01: "invalid"})

    def test_encoded_by_id_valid(self) -> None:
        result = self.codec.encoded_by_id({0x01: 42})
        assert result == bytearray([2, 0x01, 42])

    def test_encode_by_name_valid(self) -> None:
        result = self.codec.encode_by_name(
            {"test_property1": 42, "test_property2": 84}
        )
        assert result == (4, bytearray([0x01, 42, 0x02, 84]))

    def test_encode_by_name_invalid_name_raises_error(self) -> None:
        with pytest.raises(KeyError):
            self.codec.encode_by_name({"invalid_property": 42})

    def test_encode_by_name_invalid_data_raises_error(self) -> None:
        with pytest.raises(EncodeError):
            self.codec.encode_by_name({"test_property1": "invalid"})

    def test_encoded_by_name_valid(self) -> None:
        result = self.codec.encoded_by_name({"test_property1": 42})
        assert result == bytearray([2, 0x01, 42])

    def test_decode_for_name_valid(self) -> None:
        result = self.codec.decode_for_name(bytearray([4, 0x01, 42, 0x02, 84]))
        assert result == (5, {"test_property1": 42, "test_property2": 84})

    def test_decode_for_name_invalid_id_raises_error(self) -> None:
        with pytest.raises(KeyError):
            self.codec.decode_for_name(bytearray([2, 0x03, 42]))

    def test_decode_for_name_invalid_data_raises_error(self) -> None:
        with pytest.raises(DecodeError):
            self.codec.decode_for_name(bytearray([1, 0x01]))

    def test_decode_for_name_invalid_length(self) -> None:
        with pytest.raises(IndexError):
            self.codec.decode_for_name(bytearray([1]))

    def test_decode_for_name_two_multiple(self) -> None:
        result = self.codec.decode_for_name(bytearray([4, 0x01, 42, 0x01, 42]))
        assert result == (5, {"test_property1": [42, 42]})

    def test_decode_for_name_three_multiple(self) -> None:
        result = self.codec.decode_for_name(
            bytearray([6, 0x01, 42, 0x01, 42, 0x01, 42])
        )
        assert result == (7, {"test_property1": [42, 42, 42]})

    def test_real_property(self) -> None:
        result = PAYLOAD_FORMAT_ID.encode(1)
        assert result == bytearray([0x01, 1])
        length, decoded = PAYLOAD_FORMAT_ID.decode(bytearray([0x01, 1]))
        assert length == 2
        assert decoded == 1
