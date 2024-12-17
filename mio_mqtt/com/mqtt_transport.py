from abc import ABCMeta, abstractmethod
from collections.abc import Awaitable, Callable
from typing import Type, TypeAlias

from mio_mqtt.packet.packet import Packet
from mio_mqtt.types import Address, Slots

PacketTypeMap: TypeAlias = dict[int, Type[Packet]]
ReceiverCallback: TypeAlias = Callable[[Packet], Awaitable[None]]


class MQTTTransport(metaclass=ABCMeta):
    __slots__: Slots = (
        "_addr",
        "_cb",
        "_packet_type_map",
    )

    def __init__(self, addr: Address, cb: ReceiverCallback) -> None:
        self._addr: Address = addr
        self._cb: ReceiverCallback = cb

        self._packet_type_map: PacketTypeMap = self._gather_packet_type_map()

    @staticmethod
    def _gather_packet_type_map() -> PacketTypeMap:
        packet_stack: list[Type[Packet]] = [Packet]  # type: ignore[type-abstract]
        packet_type_map: PacketTypeMap = {}
        while 0 < len(packet_stack):
            current_packet: Type[Packet] = packet_stack.pop(0)
            subclasses: list[Type[Packet]] = current_packet.__subclasses__()

            if 0 == len(subclasses):
                packet_type_map[current_packet.TYPE] = current_packet
            else:
                packet_stack.extend(subclasses)

        return packet_type_map

    @abstractmethod
    async def open(self) -> None:
        raise NotImplementedError()

    @abstractmethod
    async def close(self) -> None:
        raise NotImplementedError()

    @abstractmethod
    async def send(self, packet: Packet) -> None:
        raise NotImplementedError()

    @abstractmethod
    async def wait_closed(self) -> None:
        raise NotImplementedError()
