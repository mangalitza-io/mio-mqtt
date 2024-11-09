from typing import Literal

from aio_mqtt.types import Slots


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


def encode_string(__str: str) -> bytes:
    try:
        b_data: bytes = __str.encode("utf-8")
    except AttributeError:
        raise EncodeTypeError(__str)
    except UnicodeEncodeError:
        raise EncodeValueError(__str)

    try:
        return len(b_data).to_bytes(length=2, byteorder="big") + b_data
    except OverflowError:
        raise EncodeOverflowError()
    except TypeError:
        raise EncodeTypeError()


# TODO use it
def encode_string_arr(__str: str) -> bytearray:
    b_data: bytes = __str.encode("utf-8")
    res_arr: bytearray = bytearray(2 + len(b_data))
    res_arr[0:2] = len(b_data).to_bytes(length=2, byteorder="big")
    res_arr[2:] = b_data
    return res_arr


def _encode_byte(
    __int: int, length: int, byteorder: Literal["little", "big"]
) -> bytes:
    try:
        return __int.to_bytes(length=length, byteorder=byteorder)
    except AttributeError:
        raise EncodeTypeError()
    except OverflowError:
        raise EncodeOverflowError()


def encode_one_byte(__int: int) -> bytes:
    return _encode_byte(__int, length=1, byteorder="big")


def encode_two_byte(__int: int) -> bytes:
    return _encode_byte(__int, length=2, byteorder="big")


def encode_four_byte(__int: int) -> bytes:
    return _encode_byte(__int, length=4, byteorder="big")


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
