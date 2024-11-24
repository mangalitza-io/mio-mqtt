from asyncio import AbstractEventLoop
from ssl import SSLContext
from typing import Any, TypeAlias

All: TypeAlias = tuple[str, ...]
Slots: TypeAlias = tuple[str, ...]
DictStrObject: TypeAlias = dict[str, object]

Length: TypeAlias = int

SockOpt: TypeAlias = tuple[int, int, int | bytes]
SockOpts: TypeAlias = tuple[SockOpt, ...]
Address: TypeAlias = tuple[object, ...] | str | bytes
AbstractEventLoopOrNone: TypeAlias = AbstractEventLoop | None
