# mypy: disable-error-code="unused-ignore, import-untyped, misc"
from typing import Protocol, Type, TypeAlias, cast

from mio_mqtt.types import All, Slots

__all__: All = (
    "JsonType",
    "JsonError",
    "JsonDecodeError",
    "JsonEncodeError",
    "JsonLib",
    "json_lib",
    "dumps",
    "loads",
)

JsonType: TypeAlias = (
    dict[str, "JsonType"] | list["JsonType"] | str | int | float | bool | None
)


class JsonError(ValueError):
    __slots__: Slots = tuple()


class JsonDecodeError(JsonError):
    __slots__: Slots = tuple()


class JsonEncodeError(JsonError):
    __slots__: Slots = tuple()


class _JsonLoads(Protocol):
    @staticmethod
    def __call__(data: bytes) -> JsonType: ...


class _JsonDumps(Protocol):
    @staticmethod
    def __call__(data: JsonType) -> bytes: ...


_JsonMethods: TypeAlias = tuple[_JsonLoads, _JsonDumps]
_Errors: TypeAlias = Type[Exception] | tuple[Type[Exception], ...]


class JsonLib:
    """
    Rank    Library
    1       orjson
    2       python-rapidjson
    3       ujson
    4       simplejson
    5       built-in json
    """

    dumps: _JsonDumps
    loads: _JsonLoads
    __slots__: Slots = (
        "dumps",
        "loads",
    )

    def __init__(self, json_codec: str | None = None) -> None:
        if json_codec is not None:
            self.loads, self.dumps = getattr(self, f"_get_{json_codec}")()
        elif json_codec is None:
            json_order_by_speed: tuple[str, ...] = (
                "orjson",
                "rapidjson",
                "ujson",
                "simplejson",
                "json",
            )
            for json_codec in json_order_by_speed:
                try:
                    self.loads, self.dumps = getattr(
                        self, f"_get_{json_codec}"
                    )()
                except (ImportError, ModuleNotFoundError):
                    continue
                else:
                    break

        if self.loads is None or self.dumps is None:
            raise AttributeError()

    @staticmethod
    def _get_orjson() -> _JsonMethods:
        from orjson import JSONDecodeError, JSONEncodeError, dumps, loads

        def _l(data: bytes) -> JsonType:
            try:
                return cast(JsonType, loads(data))
            except (JSONDecodeError, TypeError):  # type: ignore[misc]
                raise JsonDecodeError()

        def _d(data: JsonType) -> bytes:
            try:
                return dumps(data)  # type: ignore[misc,no-any-return]
            except (JSONEncodeError, TypeError):  # type: ignore[misc]
                raise JsonEncodeError()

        return _l, _d

    @staticmethod
    def _create_func(
        loads_func: _JsonLoads,
        dumps_func: _JsonDumps,
        decode_error: _Errors,
        encode_error: _Errors,
    ) -> _JsonMethods:
        def _l(data: bytes) -> JsonType:
            try:
                return loads_func(data)
            except decode_error:
                raise JsonDecodeError()

        def _d(data: JsonType) -> bytes:
            try:
                return dumps_func(data)
            except encode_error:
                raise JsonEncodeError()

        return _l, _d

    @classmethod
    def _get_rapidjson(cls) -> _JsonMethods:
        from rapidjson import JSONDecodeError, dumps, loads

        return cls._create_func(
            loads_func=cast(_JsonLoads, loads),
            dumps_func=cast(
                _JsonDumps, lambda data: dumps(data).encode("utf_8")
            ),
            decode_error=(JSONDecodeError, TypeError),
            encode_error=(TypeError, OverflowError),
        )

    @classmethod
    def _get_ujson(cls) -> _JsonMethods:
        from ujson import JSONDecodeError, dumps, loads

        return cls._create_func(
            loads_func=cast(_JsonLoads, loads),
            dumps_func=cast(
                _JsonDumps, lambda data: dumps(data).encode("utf_8")
            ),
            decode_error=(JSONDecodeError, TypeError),
            encode_error=(TypeError, OverflowError),
        )

    @classmethod
    def _get_simplejson(cls) -> _JsonMethods:
        from simplejson import JSONDecodeError, dumps, loads

        return cls._create_func(
            loads_func=cast(_JsonLoads, loads),
            dumps_func=cast(
                _JsonDumps, lambda data: dumps(data).encode("utf_8")
            ),
            decode_error=(JSONDecodeError, TypeError),
            encode_error=(TypeError, OverflowError),
        )

    @classmethod
    def _get_json(cls) -> _JsonMethods:
        from json import JSONDecodeError, dumps, loads

        return cls._create_func(
            loads_func=cast(_JsonLoads, loads),
            dumps_func=cast(
                _JsonDumps, lambda data: dumps(data).encode("utf_8")
            ),
            decode_error=(JSONDecodeError, TypeError),
            encode_error=(TypeError, OverflowError),
        )


json_lib: JsonLib = JsonLib()
dumps: _JsonDumps = json_lib.dumps
loads: _JsonLoads = json_lib.loads
