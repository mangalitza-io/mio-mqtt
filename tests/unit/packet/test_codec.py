from abc import abstractmethod

import pytest

from mio_mqtt.packet.codec import (
    BinaryCodec,
    Codec,
    CodecError,
    DecodeError,
    DecodeIndexError,
    DecodeOverflowError,
    DecodeTypeError,
    DecodeValueError,
    EncodeAttributeError,
    EncodeError,
    EncodeOverflowError,
    EncodeTypeError,
    EncodeValueError,
    FourByteCodec,
    OneByteCodec,
    StrCodec,
    StrPairCodec,
    TwoByteCodec,
    VariableByteCodec,
    _IntCodec,
)


class TestCodecError:
    def test_codec_error_inherits_from_exception(self) -> None:
        assert issubclass(CodecError, Exception)

    def test_codec_error_can_be_initialized(self) -> None:
        err: CodecError = CodecError()
        assert isinstance(err, CodecError)

    def test_codec_error_can_be_raised(self) -> None:
        with pytest.raises(CodecError) as exc_info:
            raise CodecError()
        assert exc_info.type is CodecError


class TestEncodeError:
    def test_encode_error_inherits_from_codec_error(self) -> None:
        assert issubclass(EncodeError, CodecError)

    def test_encode_error_can_be_initialized(self) -> None:
        err: EncodeError = EncodeError()
        assert isinstance(err, CodecError)

    def test_encode_error_can_be_raised(self) -> None:
        with pytest.raises(EncodeError) as exc_info:
            raise EncodeError()
        assert exc_info.type is EncodeError


class TestEncodeTypeError:
    def test_encode_type_error_inherits_from_encode_error(self) -> None:
        assert issubclass(EncodeTypeError, EncodeError)

    def test_encode_type_error_inherits_from_type_error(self) -> None:
        assert issubclass(EncodeTypeError, TypeError)

    def test_encode_type_error_can_be_initialized(self) -> None:
        err: EncodeTypeError = EncodeTypeError()
        assert isinstance(err, CodecError)

    def test_encode_type_error_can_be_raised(self) -> None:
        with pytest.raises(EncodeTypeError) as exc_info:
            raise EncodeTypeError()
        assert exc_info.type is EncodeTypeError


class TestEncodeAttributeError:
    def test_encode_type_error_inherits_from_encode_error(self) -> None:
        assert issubclass(EncodeAttributeError, EncodeError)

    def test_encode_type_error_inherits_from_type_error(self) -> None:
        assert issubclass(EncodeAttributeError, AttributeError)

    def test_encode_type_error_can_be_initialized(self) -> None:
        err: EncodeAttributeError = EncodeAttributeError()
        assert isinstance(err, CodecError)

    def test_encode_type_error_can_be_raised(self) -> None:
        with pytest.raises(EncodeAttributeError) as exc_info:
            raise EncodeAttributeError()
        assert exc_info.type is EncodeAttributeError


class TestEncodeValueError:
    def test_encode_value_error_inherits_from_encode_error(self) -> None:
        assert issubclass(EncodeValueError, EncodeError)

    def test_encode_value_error_inherits_from_value_error(self) -> None:
        assert issubclass(EncodeValueError, ValueError)

    def test_encode_value_error_can_be_initialized(self) -> None:
        err: EncodeValueError = EncodeValueError()
        assert isinstance(err, EncodeError)

    def test_encode_value_error_can_be_raised(self) -> None:
        with pytest.raises(EncodeValueError) as exc_info:
            raise EncodeValueError()
        assert exc_info.type is EncodeValueError


class TestEncodeOverflowError:
    def test_encode_overflow_error_inherits_from_encode_error(self) -> None:
        assert issubclass(EncodeOverflowError, EncodeError)

    def test_encode_overflow_error_inherits_from_overflow_error(self) -> None:
        assert issubclass(EncodeOverflowError, OverflowError)

    def test_encode_overflow_error_can_be_initialized(self) -> None:
        err: EncodeOverflowError = EncodeOverflowError()
        assert isinstance(err, EncodeError)

    def test_encode_overflow_error_can_be_raised(self) -> None:
        with pytest.raises(EncodeOverflowError) as exc_info:
            raise EncodeOverflowError()
        assert exc_info.type is EncodeOverflowError


class TestDecodeError:
    def test_encode_error_inherits_from_codec_error(self) -> None:
        assert issubclass(DecodeError, CodecError)

    def test_encode_error_can_be_initialized(self) -> None:
        err: DecodeError = DecodeError()
        assert isinstance(err, CodecError)

    def test_encode_error_can_be_raised(self) -> None:
        with pytest.raises(DecodeError) as exc_info:
            raise DecodeError()
        assert exc_info.type is DecodeError


class TestDecodeIndexError:
    def test_decode_index_error_inherits_from_decode_error(self) -> None:
        assert issubclass(DecodeIndexError, DecodeError)

    def test_decode_index_error_inherits_from_index_error(self) -> None:
        assert issubclass(DecodeIndexError, IndexError)

    def test_decode_index_error_can_be_initialized(self) -> None:
        err: DecodeIndexError = DecodeIndexError()
        assert isinstance(err, DecodeError)

    def test_decode_index_error_can_be_raised(self) -> None:
        with pytest.raises(DecodeIndexError) as exc_info:
            raise DecodeIndexError()
        assert exc_info.type is DecodeIndexError


class TestDecodeTypeError:
    def test_decode_type_error_inherits_from_decode_error(self) -> None:
        assert issubclass(DecodeTypeError, DecodeError)

    def test_decode_type_error_inherits_from_type_error(self) -> None:
        assert issubclass(DecodeTypeError, TypeError)

    def test_decode_type_error_can_be_initialized(self) -> None:
        err: DecodeTypeError = DecodeTypeError()
        assert isinstance(err, DecodeError)

    def test_decode_type_error_can_be_raised(self) -> None:
        with pytest.raises(DecodeTypeError) as exc_info:
            raise DecodeTypeError()
        assert exc_info.type is DecodeTypeError


class TestDecodeValueError:
    def test_decode_value_error_inherits_from_decode_error(self) -> None:
        assert issubclass(DecodeValueError, DecodeError)

    def test_decode_value_error_inherits_from_value_error(self) -> None:
        assert issubclass(DecodeValueError, ValueError)

    def test_decode_value_error_can_be_initialized(self) -> None:
        err: DecodeValueError = DecodeValueError()
        assert isinstance(err, DecodeError)

    def test_decode_value_error_can_be_raised(self) -> None:
        with pytest.raises(DecodeValueError) as exc_info:
            raise DecodeValueError()
        assert exc_info.type is DecodeValueError


class TestDecodeOverflowError:
    def test_decode_overflow_error_inherits_from_decode_error(self) -> None:
        assert issubclass(DecodeOverflowError, DecodeError)

    def test_decode_overflow_error_inherits_from_overflow_error(self) -> None:
        assert issubclass(DecodeOverflowError, OverflowError)

    def test_decode_overflow_error_can_be_initialized(self) -> None:
        err: DecodeOverflowError = DecodeOverflowError()
        assert isinstance(err, DecodeError)

    def test_decode_overflow_error_can_be_raised(self) -> None:
        with pytest.raises(DecodeOverflowError) as exc_info:
            raise DecodeOverflowError()
        assert exc_info.type is DecodeOverflowError


class TestCodec:
    def test_codec_is_abstract_class(self) -> None:
        with pytest.raises(TypeError):
            Codec()  # type: ignore[abstract]

    def test_subclass_without_implementation_cannot_instantiate(self) -> None:
        class IncompleteCodec(Codec):
            @classmethod
            def encode(cls, __data: object) -> bytearray:
                return bytearray()

        with pytest.raises(TypeError):
            IncompleteCodec()  # type: ignore[abstract]

    def test_subclass_with_implementation_can_instantiate(self) -> None:
        class CompleteCodec(Codec):
            @classmethod
            def encode(cls, __data: object) -> bytearray:
                return bytearray(str(__data), "utf-8")

            @classmethod
            def decode(cls, __bytearray: bytearray) -> tuple[int, object]:
                return len(__bytearray), __bytearray.decode("utf-8")

        codec = CompleteCodec()
        assert isinstance(codec, CompleteCodec)

    def test_encode_method_of_subclass(self) -> None:
        class ExampleCodec(Codec):
            @classmethod
            def encode(cls, __data: object) -> bytearray:
                return bytearray(str(__data), "utf-8")

            @classmethod
            def decode(cls, __bytearray: bytearray) -> tuple[int, object]:
                return len(__bytearray), __bytearray.decode("utf-8")

        codec = ExampleCodec()
        data = "test data"
        encoded = codec.encode(data)
        assert isinstance(encoded, bytearray)
        assert encoded == bytearray(data, "utf-8")

    def test_decode_method_of_subclass(self) -> None:
        class ExampleCodec(Codec):
            @classmethod
            def encode(cls, __data: object) -> bytearray:
                return bytearray(str(__data), "utf-8")

            @classmethod
            def decode(cls, __bytearray: bytearray) -> tuple[int, object]:
                return len(__bytearray), __bytearray.decode("utf-8")

        codec = ExampleCodec()
        byte_data = bytearray("test data", "utf-8")
        decoded_length, decoded_object = codec.decode(byte_data)
        assert decoded_length == len(byte_data)
        assert decoded_object == "test data"

    def test_custom_subclass_encode_decode(self) -> None:
        class ReverseCodec(Codec):
            @classmethod
            def encode(cls, __data: object) -> bytearray:
                data_str = str(__data)[::-1]
                return bytearray(data_str, "utf-8")

            @classmethod
            def decode(cls, __bytearray: bytearray) -> tuple[int, object]:
                reversed_str = __bytearray.decode("utf-8")[::-1]
                return len(__bytearray), reversed_str

        codec = ReverseCodec()
        data = "hello world"
        encoded = codec.encode(data)
        assert encoded == bytearray("dlrow olleh", "utf-8")

        length, decoded = codec.decode(encoded)
        assert length == len(encoded)
        assert decoded == "hello world"


class TestBinaryCodec:
    def test_encode_valid_data(self) -> None:
        data = b"test"
        encoded = BinaryCodec.encode(data)
        assert isinstance(encoded, bytearray)
        expected_length = len(data).to_bytes(
            length=BinaryCodec.L_INT_LENGTH,
            byteorder=BinaryCodec.L_INT_BYTEORDER,
        )
        assert encoded[: BinaryCodec.L_INT_LENGTH] == expected_length
        assert encoded[BinaryCodec.L_INT_LENGTH :] == data

    def test_encode_empty_data(self) -> None:
        data = b""
        encoded = BinaryCodec.encode(data)
        assert isinstance(encoded, bytearray)
        expected_length = (0).to_bytes(
            length=BinaryCodec.L_INT_LENGTH,
            byteorder=BinaryCodec.L_INT_BYTEORDER,
        )
        assert encoded[: BinaryCodec.L_INT_LENGTH] == expected_length
        assert encoded[BinaryCodec.L_INT_LENGTH :] == data

    def test_encode_large_data_raises_overflow_error(self) -> None:
        data = b"x" * (2**16)
        with pytest.raises(EncodeOverflowError):
            BinaryCodec.encode(data)

    def test_encode_invalid_data_type_raises_type_error(self) -> None:
        with pytest.raises(EncodeTypeError):
            BinaryCodec.encode("invalid_type")  # type: ignore[arg-type]
        with pytest.raises(EncodeTypeError):
            BinaryCodec.encode(None)  # type: ignore[arg-type]

    def test_decode_valid_data(self) -> None:
        data = b"test"
        length = len(data).to_bytes(
            length=BinaryCodec.L_INT_LENGTH,
            byteorder=BinaryCodec.L_INT_BYTEORDER,
        )
        encoded = bytearray(length + data)
        decoded_length, decoded_data = BinaryCodec.decode(encoded)
        assert decoded_length == len(encoded)
        assert decoded_data == bytearray(data)

    def test_decode_empty_data(self) -> None:
        data = b""
        length = len(data).to_bytes(
            length=BinaryCodec.L_INT_LENGTH,
            byteorder=BinaryCodec.L_INT_BYTEORDER,
        )
        encoded = bytearray(length + data)
        decoded_length, decoded_data = BinaryCodec.decode(encoded)
        assert decoded_length == len(encoded)
        assert decoded_data == bytearray(data)

    def test_decode_invalid_length_raises_value_error(self) -> None:
        encoded = bytearray([0xFF, 0xFF]) + b"invalid_data"
        with pytest.raises(DecodeIndexError):
            BinaryCodec.decode(encoded)

    def test_decode_index_error_on_short_data(self) -> None:
        encoded = bytearray([0x00, 0x02]) + b"a"
        with pytest.raises((DecodeIndexError, DecodeValueError)):
            BinaryCodec.decode(encoded)

    def test_decode_value_error_on_mismatched_length(self) -> None:
        length = (5).to_bytes(
            length=BinaryCodec.L_INT_LENGTH,
            byteorder=BinaryCodec.L_INT_BYTEORDER,
        )
        encoded = bytearray(length + b"123")
        with pytest.raises(DecodeIndexError):
            BinaryCodec.decode(encoded)

    def test_decode_index_error_on_missing_length_field(self) -> None:
        """Test decoding when the bytearray is too short to contain the length field."""
        encoded = bytearray([0x00])  # Less than 2 bytes for length field
        with pytest.raises(DecodeIndexError):
            BinaryCodec.decode(encoded)

    def test_encode_and_decode_consistency(self) -> None:
        data = b"test_consistency"
        encoded = BinaryCodec.encode(data)
        decoded_length, decoded_data = BinaryCodec.decode(encoded)
        assert decoded_length == len(encoded)
        assert decoded_data == bytearray(data)

    def test_encode_raises_overflow_error(self) -> None:
        with pytest.raises(EncodeOverflowError):
            BinaryCodec.encode(b"x" * (2**16 + 1))

    def test_decode_too_short_raises_index_error(self) -> None:
        with pytest.raises(DecodeIndexError):
            BinaryCodec.decode(bytearray([0x00]))

    def test_decode_index_error_on_insufficient_data(self) -> None:
        encoded = bytearray([0x00, 0x05]) + b"12"
        with pytest.raises(DecodeIndexError):
            BinaryCodec.decode(encoded)


class TestStrCodec:
    def test_encode_valid_string(self) -> None:
        data = "test string"
        encoded = StrCodec.encode(data)
        assert isinstance(encoded, bytearray)
        expected_length = len(data.encode(StrCodec.ENCODING)).to_bytes(
            length=BinaryCodec.L_INT_LENGTH,
            byteorder=BinaryCodec.L_INT_BYTEORDER,
        )
        assert encoded[: BinaryCodec.L_INT_LENGTH] == expected_length

    def test_encode_empty_string(self) -> None:
        data = ""
        encoded = StrCodec.encode(data)
        assert isinstance(encoded, bytearray)
        expected_length = (0).to_bytes(
            length=BinaryCodec.L_INT_LENGTH,
            byteorder=BinaryCodec.L_INT_BYTEORDER,
        )
        assert encoded[: BinaryCodec.L_INT_LENGTH] == expected_length
        assert encoded[BinaryCodec.L_INT_LENGTH :] == b""

    def test_encode_invalid_type_raises_type_error(self) -> None:
        with pytest.raises(EncodeAttributeError):
            StrCodec.encode(12345)  # type: ignore[arg-type]

    def test_encode_unicode_error_raises_index_error(self) -> None:
        invalid_str = "test \udc80"
        with pytest.raises(EncodeValueError):
            StrCodec.encode(invalid_str)

    def test_decode_valid_encoded_string(self) -> None:
        data = "test string"
        encoded = StrCodec.encode(data)
        decoded_length, decoded_string = StrCodec.decode(encoded)
        assert decoded_length == len(encoded)
        assert decoded_string == data

    def test_decode_empty_string(self) -> None:
        data = ""
        encoded = StrCodec.encode(data)
        decoded_length, decoded_string = StrCodec.decode(encoded)
        assert decoded_length == len(encoded)
        assert decoded_string == data

    def test_decode_invalid_bytearray_raises_index_error(self) -> None:
        invalid_bytearray = bytearray([0xFF, 0xFF]) + b"invalid_data"
        with pytest.raises(DecodeIndexError):
            StrCodec.decode(invalid_bytearray)

    def test_decode_unicode_error_raises_value_error(self) -> None:
        invalid_data = bytearray([0x00, 0x01]) + b"\x80"
        with pytest.raises(DecodeValueError):
            StrCodec.decode(invalid_data)

    def test_encode_and_decode_consistency(self) -> None:
        data = "test consistency"
        encoded = StrCodec.encode(data)
        decoded_length, decoded_string = StrCodec.decode(encoded)
        assert decoded_length == len(encoded)
        assert decoded_string == data


class TestStrPairCodec:
    def test_encode_valid_tuple(self) -> None:
        data = ("key", "value")
        encoded = StrPairCodec.encode(data)
        assert isinstance(encoded, bytearray)
        key_encoded = StrCodec.encode(data[0])
        value_encoded = StrCodec.encode(data[1])
        assert encoded == key_encoded + value_encoded

    def test_encode_empty_tuple(self) -> None:
        data = ("", "")
        encoded = StrPairCodec.encode(data)
        assert isinstance(encoded, bytearray)
        key_encoded = StrCodec.encode(data[0])
        value_encoded = StrCodec.encode(data[1])
        assert encoded == key_encoded + value_encoded

    def test_encode_invalid_type_raises_type_error(self) -> None:
        with pytest.raises(EncodeValueError):
            StrPairCodec.encode("not_a_tuple")  # type: ignore[arg-type]

    def test_encode_invalid_tuple_structure_raises_value_error(self) -> None:
        with pytest.raises(EncodeValueError):
            StrPairCodec.encode(("key_only",))  # type: ignore[arg-type]

    def test_decode_valid_encoded_tuple(self) -> None:
        data = ("key", "value")
        encoded = StrPairCodec.encode(data)
        decoded_length, decoded_tuple = StrPairCodec.decode(encoded)
        assert decoded_length == len(encoded)
        assert decoded_tuple == data

    def test_decode_empty_tuple(self) -> None:
        data = ("", "")
        encoded = StrPairCodec.encode(data)
        decoded_length, decoded_tuple = StrPairCodec.decode(encoded)
        assert decoded_length == len(encoded)
        assert decoded_tuple == data

    def test_decode_partial_bytearray_raises_value_error(self) -> None:
        data = ("key", "value")
        encoded = StrPairCodec.encode(data)
        partial_encoded = encoded[: len(encoded) // 2]
        with pytest.raises((DecodeValueError, DecodeIndexError)):
            StrPairCodec.decode(partial_encoded)

    def test_encode_and_decode_consistency(self) -> None:
        data = ("key", "value")
        encoded = StrPairCodec.encode(data)
        decoded_length, decoded_tuple = StrPairCodec.decode(encoded)
        assert decoded_length == len(encoded)
        assert decoded_tuple == data

    def test_encode_iterable(self) -> None:
        key_1 = "key-1"
        value_1 = "value-1"
        key_2 = "key-2"
        value_2 = "value-2"
        data = (
            (key_1, value_1),
            (key_2, value_2),
        )
        multiple_encoded = StrPairCodec.encode(data)
        expected = (
            StrCodec.encode(key_1)
            + StrCodec.encode(value_1)
            + StrCodec.encode(key_2)
            + StrCodec.encode(value_2)
        )
        assert multiple_encoded == expected


class TestIntCodec:
    def setup_method(self) -> None:
        class CustomIntCodec(_IntCodec):
            LENGTH = 2

        self.int_codec = CustomIntCodec

    def test_encode_valid_int(self) -> None:
        result = self.int_codec.encode(42)
        assert result == (42).to_bytes(
            length=self.int_codec.LENGTH, byteorder=self.int_codec.BYTEORDER
        )

    def test_encode_large_int_raises_overflow_error(self) -> None:
        large_int: int = 2 ** (8 * self.int_codec.LENGTH)
        with pytest.raises(EncodeOverflowError):
            self.int_codec.encode(large_int)

    def test_encode_negative_int_raises_error_if_unsigned(self) -> None:
        with pytest.raises(EncodeOverflowError):
            self.int_codec.encode(-1)

    def test_encode_invalid_type_raises_error(self) -> None:
        with pytest.raises(EncodeTypeError):
            self.int_codec.encode("invalid")  # type: ignore[arg-type]

    def test_decode_valid_bytearray(self) -> None:
        test_bytearray = (1234).to_bytes(
            length=self.int_codec.LENGTH, byteorder=self.int_codec.BYTEORDER
        )
        length, decoded_int = self.int_codec.decode(bytearray(test_bytearray))
        assert length == self.int_codec.LENGTH
        assert decoded_int == 1234

    def test_decode_with_insufficient_length_raises_index_error(self) -> None:
        short_bytearray = (42).to_bytes(
            length=self.int_codec.LENGTH - 1,
            byteorder=self.int_codec.BYTEORDER,
        )
        with pytest.raises(DecodeIndexError):
            self.int_codec.decode(bytearray(short_bytearray))

    def test_decode_with_extra_bytes_ignores_excess(self) -> None:
        test_bytearray = (1234).to_bytes(
            length=self.int_codec.LENGTH, byteorder=self.int_codec.BYTEORDER
        )
        extended_bytearray = bytearray(test_bytearray + b"\x00" * 5)
        length, decoded_int = self.int_codec.decode(extended_bytearray)
        assert length == self.int_codec.LENGTH
        assert decoded_int == 1234

    def test_decode_invalid_type_raises_error(self) -> None:
        with pytest.raises(DecodeTypeError):
            self.int_codec.decode("not a bytearray")  # type: ignore[arg-type]

    def test_decode_non_iterable_raises_error(self) -> None:
        with pytest.raises(DecodeTypeError):
            self.int_codec.decode(None)  # type: ignore[arg-type]


class TestVariableByteCodec:
    def test_encode_single_byte_values(self) -> None:
        assert VariableByteCodec.encode(0) == bytearray([0])
        assert VariableByteCodec.encode(1) == bytearray([1])
        assert VariableByteCodec.encode(127) == bytearray([127])

    def test_encode_multi_byte_values(self) -> None:
        assert VariableByteCodec.encode(128) == bytearray([128, 1])
        assert VariableByteCodec.encode(16383) == bytearray([255, 127])
        assert VariableByteCodec.encode(2097151) == bytearray([255, 255, 127])
        assert VariableByteCodec.encode(268435455) == bytearray(
            [255, 255, 255, 127]
        )

    def test_encode_invalid_type_raises_error(self) -> None:
        with pytest.raises(EncodeTypeError):
            VariableByteCodec.encode("invalid")  # type: ignore[arg-type]

    def test_encode_negative_value_raises_error(self) -> None:
        with pytest.raises(EncodeOverflowError):
            VariableByteCodec.encode(-1)

    def test_encode_large_value_raises_error(self) -> None:
        with pytest.raises(EncodeOverflowError):
            VariableByteCodec.encode(0xFFFFFF7F + 1)

    def test_decode_single_byte_values(self) -> None:
        assert VariableByteCodec.decode(bytearray([0])) == (1, 0)
        assert VariableByteCodec.decode(bytearray([1])) == (1, 1)
        assert VariableByteCodec.decode(bytearray([127])) == (1, 127)

    def test_decode_multi_byte_values(self) -> None:
        assert VariableByteCodec.decode(bytearray([128, 1])) == (2, 128)
        assert VariableByteCodec.decode(bytearray([255, 127])) == (2, 16383)
        assert VariableByteCodec.decode(bytearray([255, 255, 127])) == (
            3,
            2097151,
        )
        assert VariableByteCodec.decode(bytearray([255, 255, 255, 127])) == (
            4,
            268435455,
        )

    def test_decode_incomplete_byte_sequence_raises_error(self) -> None:
        with pytest.raises(ValueError):
            VariableByteCodec.decode(bytearray([128]))

    def test_decode_invalid_length(self) -> None:
        with pytest.raises(ValueError):
            VariableByteCodec.decode(bytearray([]))

    def test_decode_invalid_large_multiplier_raises_error(self) -> None:
        with pytest.raises(ValueError):
            VariableByteCodec.decode(bytearray([128, 128, 128, 128, 1]))

    def test_encode_and_decode_consistency(self) -> None:
        values = [0, 1, 127, 128, 16383, 2097151, 268435455]
        for value in values:
            encoded = VariableByteCodec.encode(value)
            decoded_length, decoded_value = VariableByteCodec.decode(encoded)
            assert decoded_length == len(encoded)
            assert decoded_value == value

    def test_boundary_values(self) -> None:
        assert VariableByteCodec.encode(268435455) == bytearray(
            [255, 255, 255, 127]
        )
        assert VariableByteCodec.decode(bytearray([255, 255, 255, 127])) == (
            4,
            268435455,
        )

    def test_invalid_type_decode(self) -> None:
        with pytest.raises(TypeError):
            VariableByteCodec.decode("invalid")  # type: ignore[arg-type]
