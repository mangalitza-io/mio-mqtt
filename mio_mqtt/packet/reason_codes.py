from collections.abc import Iterable, Iterator, Mapping
from enum import Enum

from mio_mqtt.types import All, Slots

__all__: All = (
    "ReasonCodeError",
    "ReasonCodeTypeError",
    "ReasonCodeValueError",
    "ReasonCodeKeyError",
    "ReasonCode",
    "ReasonCodes",
    "SUCCESS",
    "NORMAL_DISCONNECTION",
    "GRANTED_QOS_0",
    "GRANTED_QOS_1",
    "GRANTED_QOS_2",
    "DISCONNECT_WITH_WILL_MESSAGE",
    "NO_MATCHING_SUBSCRIBERS",
    "NO_SUBSCRIPTION_EXISTED",
    "CONTINUE_AUTHENTICATION",
    "RE_AUTHENTICATE",
    "UNSPECIFIED_ERROR",
    "MALFORMED_PACKET",
    "PROTOCOL_ERROR",
    "IMPLEMENTATION_SPECIFIC_ERROR",
    "UNSUPPORTED_PROTOCOL_VERSION",
    "CLIENT_IDENTIFIER_NOT_VALID",
    "BAD_USER_NAME_OR_PASSWORD",
    "NOT_AUTHORIZED",
    "SERVER_UNAVAILABLE",
    "SERVER_BUSY",
    "BANNED",
    "SERVER_SHUTTING_DOWN",
    "BAD_AUTHENTICATION_METHOD",
    "KEEP_ALIVE_TIMEOUT",
    "SESSION_TAKEN_OVER",
    "TOPIC_FILTER_INVALID",
    "TOPIC_NAME_INVALID",
    "PACKET_IDENTIFIER_IN_USE",
    "PACKET_IDENTIFIER_NOT_FOUND",
    "RECEIVE_MAXIMUM_EXCEEDED",
    "TOPIC_ALIAS_INVALID",
    "PACKET_TOO_LARGE",
    "MESSAGE_RATE_TOO_HIGH",
    "QUOTA_EXCEEDED",
    "ADMINISTRATIVE_ACTION",
    "PAYLOAD_FORMAT_INVALID",
    "RETAIN_NOT_SUPPORTED",
    "QOS_NOT_SUPPORTED",
    "USE_ANOTHER_SERVER",
    "SERVER_MOVED",
    "SHARED_SUBSCRIPTIONS_NOT_SUPPORTED",
    "CONNECTION_RATE_EXCEEDED",
    "MAXIMUM_CONNECT_TIME",
    "SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED",
    "WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED",
)


class ReasonCodeError(Exception):
    __slots__: Slots = tuple()


class ReasonCodeTypeError(ReasonCodeError, TypeError):
    __slots__: Slots = tuple()


class ReasonCodeValueError(ReasonCodeError, ValueError):
    __slots__: Slots = tuple()


class ReasonCodeKeyError(ReasonCodeError, KeyError):
    __slots__: Slots = tuple()


class ReasonCode:
    __slots__: Slots = (
        "_code",
        "_name",
    )

    def __init__(self, code: int, name: str) -> None:
        self._code: int = code
        self._name: str = name

    @property
    def code(self) -> int:
        return self._code

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_success(self) -> bool:
        return 0x80 > self._code

    @property
    def is_failure(self) -> bool:
        return 0x80 <= self._code


class ReasonCodes(Mapping[int, ReasonCode]):
    __slots__: Slots = (
        "_reason_codes",
        "_reason_codes_by_code",
    )

    def __init__(self, reason_codes: Iterable[ReasonCode]) -> None:
        self._reason_codes: tuple[ReasonCode, ...] = tuple(reason_codes)
        try:
            self._reason_codes_by_code: Mapping[int, ReasonCode] = {
                reason_code.code: reason_code
                for reason_code in self._reason_codes
            }
        except AttributeError:
            raise ReasonCodeTypeError()

        for reason_code in self._reason_codes:
            if not isinstance(reason_code, ReasonCode):
                raise ReasonCodeTypeError()

        if len(self._reason_codes) != len(self._reason_codes_by_code):
            raise ReasonCodeValueError()

    def __getitem__(self, key: int) -> ReasonCode:
        try:
            return self._reason_codes_by_code[key]
        except KeyError:
            raise ReasonCodeKeyError()

    def __len__(self) -> int:
        return len(self._reason_codes)

    def __iter__(self) -> Iterator[int]:
        return iter(self._reason_codes_by_code)

    def get_reason_code(self, code: int) -> ReasonCode:
        return self.__getitem__(code)


# fmt: off
SUCCESS: ReasonCode = ReasonCode(
    code=0x00,
    name="Success"
)
NORMAL_DISCONNECTION: ReasonCode = ReasonCode(
    code=0x00,
    name="Normal disconnection"
)
GRANTED_QOS_0: ReasonCode = ReasonCode(
    code=0x00,
    name="Granted QoS 0"
)
GRANTED_QOS_1: ReasonCode = ReasonCode(
    code=0x01,
    name="Granted QoS 1"
)
GRANTED_QOS_2: ReasonCode = ReasonCode(
    code=0x02,
    name="Granted QoS 2"
)
DISCONNECT_WITH_WILL_MESSAGE: ReasonCode = ReasonCode(
    code=0x04,
    name="Disconnect with Will Message"
)
NO_MATCHING_SUBSCRIBERS: ReasonCode = ReasonCode(
    code=0x10,
    name="No matching subscribers"
)
NO_SUBSCRIPTION_EXISTED: ReasonCode = ReasonCode(
    code=0x11,
    name="No subscription existed"
)
CONTINUE_AUTHENTICATION: ReasonCode = ReasonCode(
    code=0x18,
    name="Continue authentication"
)
RE_AUTHENTICATE: ReasonCode = ReasonCode(
    code=0x19,
    name="Re-authenticate"
)
UNSPECIFIED_ERROR: ReasonCode = ReasonCode(
    code=0x80,
    name="Unspecified error"
)
MALFORMED_PACKET: ReasonCode = ReasonCode(
    code=0x81,
    name="Malformed Packet"
)
PROTOCOL_ERROR: ReasonCode = ReasonCode(
    code=0x82,
    name="Protocol Error"
)
IMPLEMENTATION_SPECIFIC_ERROR: ReasonCode = ReasonCode(
    code=0x83,
    name="Implementation specific error"
)
UNSUPPORTED_PROTOCOL_VERSION: ReasonCode = ReasonCode(
    code=0x84,
    name="Unsupported Protocol Version"
)
CLIENT_IDENTIFIER_NOT_VALID: ReasonCode = ReasonCode(
    code=0x85,
    name="Client Identifier not valid"
)
BAD_USER_NAME_OR_PASSWORD: ReasonCode = ReasonCode(
    code=0x86,
    name="Bad User Name or Password"
)
NOT_AUTHORIZED: ReasonCode = ReasonCode(
    code=0x87,
    name="Not authorized"
)
SERVER_UNAVAILABLE: ReasonCode = ReasonCode(
    code=0x88,
    name="Server unavailable"
)
SERVER_BUSY: ReasonCode = ReasonCode(
    code=0x89,
    name="Server busy"
)
BANNED: ReasonCode = ReasonCode(
    code=0x8A,
    name="Banned"
)
SERVER_SHUTTING_DOWN: ReasonCode = ReasonCode(
    code=0x8B,
    name="Server shutting down"
)
BAD_AUTHENTICATION_METHOD: ReasonCode = ReasonCode(
    code=0x8C,
    name="Bad authentication method"
)
KEEP_ALIVE_TIMEOUT: ReasonCode = ReasonCode(
    code=0x8D,
    name="Keep Alive timeout"
)
SESSION_TAKEN_OVER: ReasonCode = ReasonCode(
    code=0x8E,
    name="Session taken over"
)
TOPIC_FILTER_INVALID: ReasonCode = ReasonCode(
    code=0x8F,
    name="Topic Filter invalid"
)
TOPIC_NAME_INVALID: ReasonCode = ReasonCode(
    code=0x90,
    name="Topic Name invalid"
)
PACKET_IDENTIFIER_IN_USE: ReasonCode = ReasonCode(
    code=0x91,
    name="Packet Identifier in use"
)
PACKET_IDENTIFIER_NOT_FOUND: ReasonCode = ReasonCode(
    code=0x92,
    name="Packet Identifier not found"
)
RECEIVE_MAXIMUM_EXCEEDED: ReasonCode = ReasonCode(
    code=0x93,
    name="Receive Maximum exceeded"
)
TOPIC_ALIAS_INVALID: ReasonCode = ReasonCode(
    code=0x94,
    name="Topic Alias invalid"
)
PACKET_TOO_LARGE: ReasonCode = ReasonCode(
    code=0x95,
    name="Packet too large"
)
MESSAGE_RATE_TOO_HIGH: ReasonCode = ReasonCode(
    code=0x96,
    name="Message rate too high"
)
QUOTA_EXCEEDED: ReasonCode = ReasonCode(
    code=0x97,
    name="Quota exceeded"
)
ADMINISTRATIVE_ACTION: ReasonCode = ReasonCode(
    code=0x98,
    name="Administrative action"
)
PAYLOAD_FORMAT_INVALID: ReasonCode = ReasonCode(
    code=0x99,
    name="Payload format invalid"
)
RETAIN_NOT_SUPPORTED: ReasonCode = ReasonCode(
    code=0x9A,
    name="Retain not supported"
)
QOS_NOT_SUPPORTED: ReasonCode = ReasonCode(
    code=0x9B,
    name="QoS not supported"
)
USE_ANOTHER_SERVER: ReasonCode = ReasonCode(
    code=0x9C,
    name="Use another server"
)
SERVER_MOVED: ReasonCode = ReasonCode(
    code=0x9D,
    name="Server moved"
)
SHARED_SUBSCRIPTIONS_NOT_SUPPORTED: ReasonCode = ReasonCode(
    code=0x9E,
    name="Shared Subscriptions not supported"
)
CONNECTION_RATE_EXCEEDED: ReasonCode = ReasonCode(
    code=0x9F,
    name="Connection rate exceeded"
)
MAXIMUM_CONNECT_TIME: ReasonCode = ReasonCode(
    code=0xA0,
    name="Maximum connect time"
)
SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED: ReasonCode = ReasonCode(
    code=0xA1,
    name="Subscription Identifiers not supported"
)
WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED: ReasonCode = ReasonCode(
    code=0xA2,
    name="Wildcard Subscriptions not supported"
)
# fmt: on
