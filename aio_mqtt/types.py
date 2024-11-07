from asyncio import AbstractEventLoop
from ssl import SSLContext
from typing import Any, TypeAlias

All: TypeAlias = list[str]
Slots: TypeAlias = tuple[str, ...]
DictStrObject: TypeAlias = dict[str, object]


SockOpt: TypeAlias = tuple[int, int, int | bytes]
SockOpts: TypeAlias = tuple[SockOpt, ...]
Address: TypeAlias = tuple[object, ...] | str | bytes
AbstractEventLoopOrNone: TypeAlias = AbstractEventLoop | None
