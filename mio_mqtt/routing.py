from abc import ABCMeta, abstractmethod
from collections.abc import Awaitable, Callable
from typing import Generic, TypeAlias, TypeVar

from mio_mqtt.packet.packet import Packet

_T = TypeVar("_T")

Handler: TypeAlias = Callable[[Packet], Awaitable[None]]
Handlers: TypeAlias = list[Handler]


class Router(Generic[_T], metaclass=ABCMeta):
    @abstractmethod
    def insert(self, topic: str, item: _T) -> None:
        raise NotImplementedError()

    @abstractmethod
    def match(self, topic: str) -> list[_T]:
        raise NotImplementedError()


class RadixTrieRouter(Router[_T]):
    TOPIC_DELIMITER: str = "/"

    def __init__(self) -> None:
        self._children: dict[str, RadixTrieRouter[_T]] = {}
        self._handlers: list[_T] = []

    def insert(self, topic: str, item: _T) -> None:
        node: RadixTrieRouter[_T] = self
        for part in topic.split(self.TOPIC_DELIMITER):
            node = node._children.setdefault(part, RadixTrieRouter[_T]())
        node._handlers.append(item)

    def match(self, topic: str) -> list[_T]:
        matched_handlers: list[_T] = []
        parts: list[str] = topic.split(self.TOPIC_DELIMITER)
        stack: list[tuple[RadixTrieRouter[_T], int]] = [(self, 0)]

        while 0 < len(stack):
            node, depth = stack.pop()
            if depth == len(parts):
                matched_handlers.extend(node._handlers)
                continue

            part: str = parts[depth]

            trie: RadixTrieRouter[_T]
            try:
                # single level wildcard
                trie = node._children["+"]
            except KeyError:
                pass
            else:
                stack.append((trie, depth + 1))

            try:
                # multi level wildcard
                trie = node._children["#"]
            except KeyError:
                pass
            else:
                matched_handlers.extend(trie._handlers)

            try:
                trie = node._children[part]
            except KeyError:
                pass
            else:
                stack.append((trie, depth + 1))

        return matched_handlers
