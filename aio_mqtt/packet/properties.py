from collections.abc import Callable
from typing import Type, TypeAlias

from aio_mqtt.packet.codec import (
    BinaryCodec,
    Codec,
    FourByteCodec,
    Length,
    OneByteCodec,
    StrCodec,
    StrPairCodec,
    TwoByteCodec,
    VariableByteCodec,
)
from aio_mqtt.types import Slots

EncodeFunc: TypeAlias = Callable[[object], bytearray]
DecodeFunc: TypeAlias = Callable[[bytearray], tuple[Length, object]]


class Property:
    __slots__: Slots = (
        "identifier",
        "name",
        "encode",
        "decode",
    )

    def __init__(
        self,
        identifier: int,
        name: str,
        codec: Type[Codec],
    ) -> None:
        self.identifier: int = identifier
        self.name: str = name
        self.encode: EncodeFunc = codec.encode
        self.decode: DecodeFunc = codec.decode


"""
: Property = Property(
identifier=,
name=,
codec=,
)
"""

payload_format_id: Property = Property(
    identifier=0x01,
    name="payload_format_id",
    codec=OneByteCodec,
)
message_expiry_interval: Property = Property(
    identifier=0x02,
    name="message_expiry_interval",
    codec=FourByteCodec,
)
content_type: Property = Property(
    identifier=0x03,
    name="content_type",
    codec=StrCodec,
)
response_topic: Property = Property(
    identifier=0x08,
    name="response_topic",
    codec=StrCodec,
)
correlation_data: Property = Property(
    identifier=0x09,
    name="correlation_data",
    codec=BinaryCodec,
)
subscription_identifier: Property = Property(
    identifier=0x0B,
    name="subscription_identifier",
    codec=VariableByteCodec,
)
session_expiry_interval: Property = Property(
    identifier=0x11,
    name="session_expiry_interval",
    codec=FourByteCodec,
)
assigned_client_identifier: Property = Property(
    identifier=0x12,
    name="assigned_client_identifier",
    codec=StrCodec,
)
server_keep_alive: Property = Property(
    identifier=0x13,
    name="server_keep_alive",
    codec=TwoByteCodec,
)
auth_method: Property = Property(
    identifier=0x15,
    name="auth_method",
    codec=StrCodec,
)
auth_data: Property = Property(
    identifier=0x16,
    name="auth_data",
    codec=BinaryCodec,
)
request_problem_info: Property = Property(
    identifier=0x17,
    name="request_problem_info",
    codec=OneByteCodec,
)
will_delay_interval: Property = Property(
    identifier=0x18,
    name="will_delay_interval",
    codec=FourByteCodec,
)
request_response_info: Property = Property(
    identifier=0x19,
    name="request_response_info",
    codec=OneByteCodec,
)
response_info: Property = Property(
    identifier=0x1A,
    name="response_info",
    codec=StrCodec,
)
server_reference: Property = Property(
    identifier=0x1C,
    name="server_reference",
    codec=StrCodec,
)
reason_string: Property = Property(
    identifier=0x1F,
    name="reason_string",
    codec=StrCodec,
)
receive_maximum: Property = Property(
    identifier=0x21,
    name="receive_maximum",
    codec=TwoByteCodec,
)
topic_alias_maximum: Property = Property(
    identifier=0x22,
    name="topic_alias_maximum",
    codec=TwoByteCodec,
)
topic_alias: Property = Property(
    identifier=0x23,
    name="topic_alias",
    codec=TwoByteCodec,
)
max_qos: Property = Property(
    identifier=0x24,
    name="max_qos",
    codec=OneByteCodec,
)
retain_available: Property = Property(
    identifier=0x25,
    name="retain_available",
    codec=OneByteCodec,
)
user_property: Property = Property(
    identifier=0x26,
    name="user_property",
    codec=StrPairCodec,
)
maximum_packet_size: Property = Property(
    identifier=0x27,
    name="maximum_packet_size",
    codec=FourByteCodec,
)
wildcard_subscription_available: Property = Property(
    identifier=0x28,
    name="wildcard_subscription_available",
    codec=OneByteCodec,
)
sub_id_available: Property = Property(
    identifier=0x29,
    name="sub_id_available",
    codec=OneByteCodec,
)
shared_subscription_available: Property = Property(
    identifier=0x2A,
    name="shared_subscription_available",
    codec=OneByteCodec,
)
