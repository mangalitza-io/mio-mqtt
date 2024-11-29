from collections.abc import Callable, Iterable
from typing import Type, TypeAlias

from mio_mqtt.packet.codec import (
    BinaryCodec,
    Codec,
    DecodeError,
    EncodeError,
    FourByteCodec,
    Length,
    OneByteCodec,
    StrCodec,
    StrPairCodec,
    TwoByteCodec,
    VariableByteCodec,
)
from mio_mqtt.types import All, Slots

__all__: All = (
    "PropertyID",
    "PropertyName",
    "PropertyNameMap",
    "PropertyIDMap",
    "PropertyEncoded",
    "PropertyNameDecoded",
    "PropertyIDDecoded",
    "Property",
    "PropertyCodec",
    "PAYLOAD_FORMAT_ID",
    "MESSAGE_EXPIRY_INTERVAL",
    "CONTENT_TYPE",
    "RESPONSE_TOPIC",
    "CORRELATION_DATA",
    "SUBSCRIPTION_IDENTIFIER",
    "SESSION_EXPIRY_INTERVAL",
    "ASSIGNED_CLIENT_IDENTIFIER",
    "SERVER_KEEP_ALIVE",
    "AUTH_METHOD",
    "AUTH_DATA",
    "REQUEST_PROBLEM_INFO",
    "WILL_DELAY_INTERVAL",
    "REQUEST_RESPONSE_INFO",
    "RESPONSE_INFO",
    "SERVER_REFERENCE",
    "REASON_STRING",
    "RECEIVE_MAXIMUM",
    "TOPIC_ALIAS_MAXIMUM",
    "TOPIC_ALIAS",
    "MAX_QOS",
    "RETAIN_AVAILABLE",
    "USER_PROPERTY",
    "MAXIMUM_PACKET_SIZE",
    "WILDCARD_SUBSCRIPTION_AVAILABLE",
    "SUB_ID_AVAILABLE",
    "SHARED_SUBSCRIPTION_AVAILABLE",
)

_EncodeFunc: TypeAlias = Callable[[object], bytearray]
_DecodeFunc: TypeAlias = Callable[[bytearray], tuple[Length, object]]

PropertyID: TypeAlias = int
PropertyName: TypeAlias = str
PropertyNameMap: TypeAlias = dict[PropertyName, "Property"]
PropertyIDMap: TypeAlias = dict[PropertyID, "Property"]

PropertyEncoded: TypeAlias = tuple[Length, bytearray]
PropertyNameDecoded: TypeAlias = dict[PropertyName, object]
PropertyIDDecoded: TypeAlias = tuple[PropertyID, object]


class Property:
    __slots__: Slots = (
        "identifier",
        "name",
        "_encode",
        "_decode",
    )

    def __init__(
        self,
        identifier: PropertyID,
        name: PropertyName,
        codec: Type[Codec],
    ) -> None:
        self.identifier: PropertyID = identifier
        self.name: PropertyName = name
        self._encode: _EncodeFunc = codec.encode
        self._decode: _DecodeFunc = codec.decode

    def encode(self, __data: object) -> bytearray:
        arr: bytearray = bytearray()
        arr.append(self.identifier)
        arr.extend(self._encode(__data))
        return arr

    def decode(self, __bytearray: bytearray) -> tuple[Length, object]:
        try:
            identifier: int = __bytearray[0]
        except IndexError:
            raise
        if identifier != self.identifier:
            raise TypeError()
        length, obj = self._decode(__bytearray[1:])
        return length + 1, obj


class PropertyCodec:
    __slots__: Slots = (
        "_properties",
        "_properties_by_name",
        "_properties_by_id",
    )

    def __init__(self, properties: Iterable[Property]) -> None:
        self._properties: tuple[Property, ...] = tuple(properties)
        self._properties_by_name: PropertyNameMap = {
            prop.name: prop for prop in self._properties
        }
        self._properties_by_id: PropertyIDMap = {
            prop.identifier: prop for prop in self._properties
        }

    @staticmethod
    def _encode(
        ref_properties: dict[object, Property],
        properties: dict[object, object],
    ) -> PropertyEncoded:
        arr: bytearray = bytearray()
        for identification, data in properties.items():
            try:
                prop: Property = ref_properties[identification]
            except KeyError:
                raise
            try:
                b_enc: bytearray = prop.encode(data)
            except EncodeError:
                raise
            arr.extend(b_enc)
        return len(arr), arr

    @classmethod
    def _encoded(
        cls,
        ref_properties: dict[object, Property],
        properties: dict[object, object],
    ) -> bytearray:
        __b_arr: bytearray = bytearray()
        __len, __arr = cls._encode(
            ref_properties=ref_properties, properties=properties
        )
        __b_arr += VariableByteCodec.encode(__len)
        __b_arr += __arr
        return __b_arr

    def encode_by_id(self, properties: dict[int, object]) -> PropertyEncoded:
        return self._encode(
            ref_properties=self._properties_by_id,  # type: ignore[arg-type]
            properties=properties,  # type: ignore[arg-type]
        )

    def encoded_by_id(self, properties: dict[int, object]) -> bytearray:
        return self._encoded(
            ref_properties=self._properties_by_id,  # type: ignore[arg-type]
            properties=properties,  # type: ignore[arg-type]
        )

    def encode_by_name(self, properties: dict[str, object]) -> PropertyEncoded:
        return self._encode(
            ref_properties=self._properties_by_name,  # type: ignore[arg-type]
            properties=properties,  # type: ignore[arg-type]
        )

    def encoded_by_name(self, properties: dict[str, object]) -> bytearray:
        return self._encoded(
            ref_properties=self._properties_by_name,  # type: ignore[arg-type]
            properties=properties,  # type: ignore[arg-type]
        )

    def decode_for_name(
        self, b_properties: bytearray
    ) -> tuple[Length, PropertyNameDecoded]:
        b_length, length = VariableByteCodec.decode(b_properties)

        if len(b_properties) < b_length + length:
            raise IndexError()

        b_prop_arr: bytearray = b_properties[b_length : b_length + length]
        b_prop_arr_length = len(b_prop_arr)
        res: PropertyNameDecoded = {}
        i: int = 0
        while i < b_prop_arr_length:
            prop_id: int = b_prop_arr[i]
            try:
                prop: Property = self._properties_by_id[prop_id]
            except KeyError:
                raise

            try:
                d_length: Length
                d_val: object
                d_length, d_val = prop.decode(b_prop_arr[i:])
            except DecodeError:
                raise
            i += d_length
            name: PropertyName = prop.name
            try:
                res[name]
            except KeyError:
                res[name] = d_val
            else:
                before_val: object = res[name]
                if isinstance(before_val, list) is True:
                    before_val.append(d_val)
                else:
                    print(f"{[d_val] = }")
                    res[name] = [before_val, d_val]

        return b_length + length, res


PAYLOAD_FORMAT_ID: Property = Property(
    identifier=0x01,
    name="payload_format_id",
    codec=OneByteCodec,
)
MESSAGE_EXPIRY_INTERVAL: Property = Property(
    identifier=0x02,
    name="message_expiry_interval",
    codec=FourByteCodec,
)
CONTENT_TYPE: Property = Property(
    identifier=0x03,
    name="content_type",
    codec=StrCodec,
)
RESPONSE_TOPIC: Property = Property(
    identifier=0x08,
    name="response_topic",
    codec=StrCodec,
)
CORRELATION_DATA: Property = Property(
    identifier=0x09,
    name="correlation_data",
    codec=BinaryCodec,
)
SUBSCRIPTION_IDENTIFIER: Property = Property(
    identifier=0x0B,
    name="subscription_identifier",
    codec=VariableByteCodec,
)
SESSION_EXPIRY_INTERVAL: Property = Property(
    identifier=0x11,
    name="session_expiry_interval",
    codec=FourByteCodec,
)
ASSIGNED_CLIENT_IDENTIFIER: Property = Property(
    identifier=0x12,
    name="assigned_client_identifier",
    codec=StrCodec,
)
SERVER_KEEP_ALIVE: Property = Property(
    identifier=0x13,
    name="server_keep_alive",
    codec=TwoByteCodec,
)
AUTH_METHOD: Property = Property(
    identifier=0x15,
    name="auth_method",
    codec=StrCodec,
)
AUTH_DATA: Property = Property(
    identifier=0x16,
    name="auth_data",
    codec=BinaryCodec,
)
REQUEST_PROBLEM_INFO: Property = Property(
    identifier=0x17,
    name="request_problem_info",
    codec=OneByteCodec,
)
WILL_DELAY_INTERVAL: Property = Property(
    identifier=0x18,
    name="will_delay_interval",
    codec=FourByteCodec,
)
REQUEST_RESPONSE_INFO: Property = Property(
    identifier=0x19,
    name="request_response_info",
    codec=OneByteCodec,
)
RESPONSE_INFO: Property = Property(
    identifier=0x1A,
    name="response_info",
    codec=StrCodec,
)
SERVER_REFERENCE: Property = Property(
    identifier=0x1C,
    name="server_reference",
    codec=StrCodec,
)
REASON_STRING: Property = Property(
    identifier=0x1F,
    name="reason_string",
    codec=StrCodec,
)
RECEIVE_MAXIMUM: Property = Property(
    identifier=0x21,
    name="receive_maximum",
    codec=TwoByteCodec,
)
TOPIC_ALIAS_MAXIMUM: Property = Property(
    identifier=0x22,
    name="topic_alias_maximum",
    codec=TwoByteCodec,
)
TOPIC_ALIAS: Property = Property(
    identifier=0x23,
    name="topic_alias",
    codec=TwoByteCodec,
)
MAX_QOS: Property = Property(
    identifier=0x24,
    name="max_qos",
    codec=OneByteCodec,
)
RETAIN_AVAILABLE: Property = Property(
    identifier=0x25,
    name="retain_available",
    codec=OneByteCodec,
)
USER_PROPERTY: Property = Property(
    identifier=0x26,
    name="user_property",
    codec=StrPairCodec,
)
MAXIMUM_PACKET_SIZE: Property = Property(
    identifier=0x27,
    name="maximum_packet_size",
    codec=FourByteCodec,
)
WILDCARD_SUBSCRIPTION_AVAILABLE: Property = Property(
    identifier=0x28,
    name="wildcard_subscription_available",
    codec=OneByteCodec,
)
SUB_ID_AVAILABLE: Property = Property(
    identifier=0x29,
    name="sub_id_available",
    codec=OneByteCodec,
)
SHARED_SUBSCRIPTION_AVAILABLE: Property = Property(
    identifier=0x2A,
    name="shared_subscription_available",
    codec=OneByteCodec,
)
