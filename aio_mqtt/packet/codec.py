from abc import ABCMeta, abstractmethod
from typing import Literal, TypeAlias

from aio_mqtt.types import Slots

Length: TypeAlias = int
ByteOrder: TypeAlias = Literal["little", "big"]
BinaryDecoded: TypeAlias = tuple[Length, bytearray]
StrDecoded: TypeAlias = tuple[Length, str]
StrPairDecoded: TypeAlias = tuple[Length, tuple[str, str]]
IntDecoded: TypeAlias = tuple[Length, int]


class CodecError(Exception):
    __slots__: Slots = tuple()


class EncodeError(CodecError):
    __slots__: Slots = tuple()


class EncodeTypeError(EncodeError, TypeError):
    __slots__: Slots = tuple()


class EncodeValueError(EncodeError, ValueError):
    __slots__: Slots = tuple()


class EncodeOverflowError(EncodeError, OverflowError):
    __slots__: Slots = tuple()


class DecodeError(CodecError):
    __slots__: Slots = tuple()


class DecodeIndexError(DecodeError, IndexError):
    __slots__: Slots = tuple()


class DecodeTypeError(DecodeError, TypeError):
    __slots__: Slots = tuple()


class DecodeValueError(DecodeError, ValueError):
    __slots__: Slots = tuple()


class DecodeOverflowError(DecodeError, OverflowError):
    __slots__: Slots = tuple()


class Codec(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def encode(cls, __data: object) -> bytearray:
        ...

    @classmethod
    @abstractmethod
    def decode(cls, __bytearray: bytearray) -> tuple[Length, object]:
        ...


class BinaryCodec(Codec):
    L_INT_LENGTH: int = 2
    L_INT_BYTEORDER: ByteOrder = "big"
    L_INT_IS_SIGNED: bool = False

    @classmethod
    def encode(cls, __data: bytes | bytearray | memoryview) -> bytearray:  # type: ignore[override]
        __arr: bytearray = bytearray(cls.L_INT_LENGTH + len(__data))
        try:
            __arr[0:2] = len(__data).to_bytes(
                length=cls.L_INT_LENGTH, byteorder=cls.L_INT_BYTEORDER
            )
        except OverflowError:
            raise EncodeOverflowError()
        except TypeError:
            raise EncodeTypeError()

        __arr[cls.L_INT_LENGTH :] = __data
        return __arr

    @classmethod
    def decode(cls, __bytearray: bytearray) -> BinaryDecoded:
        try:
            b_length: bytes = __bytearray[0 : cls.L_INT_LENGTH]
        except IndexError:
            raise DecodeIndexError()
        try:
            length: int = int.from_bytes(
                b_length,
                byteorder=cls.L_INT_BYTEORDER,
                signed=cls.L_INT_IS_SIGNED,
            )
        except ValueError:
            raise DecodeValueError()
        except TypeError:
            raise DecodeTypeError()

        try:
            __bytes: bytes = __bytearray[
                cls.L_INT_LENGTH : cls.L_INT_LENGTH + length
            ]
        except IndexError:
            raise DecodeIndexError()
        else:
            if len(__bytes) != length:
                raise DecodeValueError()

        return cls.L_INT_LENGTH + length, bytearray(__bytes)


class StrCodec(BinaryCodec):
    ENCODING: str = "utf_8"
    ERRORS: str = "strict"

    __slots__: Slots = tuple()

    @classmethod
    def encode(cls, __data: str) -> bytearray:  # type: ignore[override]
        try:
            b__str: bytes = __data.encode(
                encoding=cls.ENCODING, errors=cls.ERRORS
            )
        except AttributeError:
            raise EncodeTypeError(__data)
        except UnicodeEncodeError:
            raise EncodeValueError(__data)

        return super(StrCodec, cls).encode(b__str)

    @classmethod
    def decode(cls, __bytearray: bytearray) -> StrDecoded:  # type: ignore[override]
        length, __arr = super(StrCodec, cls).decode(__bytearray)

        try:
            __str: str = __arr.decode(encoding=cls.ENCODING, errors=cls.ERRORS)
        except UnicodeDecodeError:
            raise DecodeValueError()

        return length, __str


class StrPairCodec(StrCodec):
    __slots__: Slots = tuple()

    @classmethod
    def encode(cls, __data: tuple[str, str]) -> bytearray:  # type: ignore[override]
        try:
            __str_key, __str_val = __data
        except ValueError:
            raise EncodeValueError()
        __arr: bytearray = bytearray()
        __arr += super(StrPairCodec, cls).encode(__str_key)
        __arr += super(StrPairCodec, cls).encode(__str_val)
        return __arr

    @classmethod
    def decode(cls, __bytearray: bytearray) -> StrPairDecoded:  # type: ignore[override]
        key_len, key_arr = super(StrPairCodec, cls).decode(__bytearray)
        val_len, val_arr = super(StrPairCodec, cls).decode(
            __bytearray[key_len:]
        )

        return key_len + val_len, (key_arr, val_arr)


class _IntCodec(Codec):
    LENGTH: int
    BYTEORDER: ByteOrder = "big"
    IS_SIGNED: bool = False

    __slots__: Slots = tuple()

    @classmethod
    def encode(cls, __data: int) -> bytearray:  # type: ignore[override]
        try:
            b_int: bytes = __data.to_bytes(
                length=cls.LENGTH, byteorder=cls.BYTEORDER
            )
        except AttributeError:
            raise EncodeTypeError()
        except OverflowError:
            raise EncodeOverflowError()

        return bytearray(b_int)

    @classmethod
    def decode(cls, __bytearray: bytearray) -> IntDecoded:
        try:
            __b_int: bytes = __bytearray[0 : cls.LENGTH]
        except IndexError:
            raise DecodeIndexError()
        except TypeError:
            raise DecodeTypeError()
        except ValueError:
            raise DecodeValueError()

        try:
            __int: int = int.from_bytes(
                bytes=__b_int, byteorder=cls.BYTEORDER, signed=cls.IS_SIGNED
            )
        except TypeError:
            raise DecodeTypeError()
        except ValueError:
            raise DecodeValueError()
        except OverflowError:
            raise DecodeOverflowError()

        return cls.LENGTH, __int


class OneByteCodec(_IntCodec):
    LENGTH: int = 1
    __slots__: Slots = tuple()


class TwoByteCodec(_IntCodec):
    LENGTH: int = 2
    __slots__: Slots = tuple()


class FourByteCodec(_IntCodec):
    LENGTH: int = 4
    __slots__: Slots = tuple()


class VariableByteCodec(Codec):
    __slots__: Slots = tuple()

    @classmethod
    def encode(cls, __data: int) -> bytearray:  # type: ignore[override]
        arr: bytearray = bytearray()
        while True:
            encoded_byte: int = __data % 128
            __data //= 128
            if 0 < __data:
                encoded_byte |= 128
            arr.append(encoded_byte)
            if 0 >= __data:
                break
        return arr

    @classmethod
    def decode(cls, __bytearray: bytearray) -> IntDecoded:
        __bytearray_length: int = len(__bytearray)
        multiplier: int = 1
        value: int = 0
        index: int = 0
        while True:
            try:
                encoded_byte: int = __bytearray[index]
            except IndexError:
                raise ValueError()
            index += 1
            value += (encoded_byte & 0x7F) * multiplier
            if multiplier > 0x200000:
                raise ValueError()
            if (encoded_byte & 0x80) == 0:
                break
            multiplier *= 0x80

        return index, value
