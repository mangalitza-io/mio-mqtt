from asyncio import AbstractEventLoop
from typing import TypeAlias

All: TypeAlias = tuple[str, ...]
Slots: TypeAlias = tuple[str, ...]
DictStrObject: TypeAlias = dict[str, object]
Length: TypeAlias = int
Buffer: TypeAlias = bytes | bytearray | memoryview

SockOpt: TypeAlias = tuple[int, int, int | bytes]
SockOpts: TypeAlias = tuple[SockOpt, ...]
Address: TypeAlias = tuple[object, ...] | str | bytes

DictStrObjectOrNone: TypeAlias = DictStrObject | None
AbstractEventLoopOrNone: TypeAlias = AbstractEventLoop | None
