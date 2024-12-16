from abc import ABCMeta, abstractmethod
from typing import TypeAlias

from mio_mqtt.types import All, Slots

__all__: All = (
    "PacketID",
    "PacketIdentifier",
    "SimplePacketID",
    "BitmapPacketID",
)

PacketID: TypeAlias = int


class PacketIdentifier(metaclass=ABCMeta):
    MAX: int = 0xFFFF
    __slots__: Slots = tuple()

    @abstractmethod
    def get_id(self) -> PacketID:
        raise NotImplementedError()

    @abstractmethod
    def release_id(self, packet_id: PacketID) -> None:
        raise NotImplementedError()

    @abstractmethod
    def reserve_id(self, packet_id: PacketID) -> None:
        raise NotImplementedError()


class SimplePacketID(PacketIdentifier):
    __slots__: Slots = (
        "_used_ids",
        "_current_id",
        "_max_plus_one",
    )

    def __init__(self) -> None:
        self._used_ids: set[PacketID] = set()
        self._current_id: PacketID = 0
        self._max_plus_one: int = self.MAX + 1

    def get_id(self) -> PacketID:
        if self.MAX == len(self._used_ids):
            raise OverflowError()
        while True:
            self._current_id = (self._current_id + 1) % self._max_plus_one

            if self._current_id not in self._used_ids:
                self._used_ids.add(self._current_id)
                return self._current_id

    def release_id(self, packet_id: PacketID) -> None:
        try:
            return self._used_ids.remove(packet_id)
        except KeyError:
            return None

    def reserve_id(self, packet_id: PacketID) -> None:
        if packet_id in self._used_ids:
            raise KeyError()
        self._used_ids.add(packet_id)


class BitmapPacketID(PacketIdentifier):
    __slots__: Slots = (
        "_bitmap",
        "_current_id",
        "_max_plus_one",
    )

    def __init__(self) -> None:
        self._bitmap: int = 0
        self._current_id: PacketID = 0
        self._max_plus_one: int = self.MAX + 1

    def get_id(self) -> PacketID:
        start_id: PacketID = self._current_id

        while True:
            self._current_id = (self._current_id + 1) % self._max_plus_one

            if not (self._bitmap & (1 << self._current_id)):
                self._bitmap |= 1 << self._current_id
                return self._current_id

            if self._current_id == start_id:
                raise OverflowError()

    def release_id(self, packet_id: PacketID) -> None:
        self._bitmap &= ~(1 << packet_id)

    def reserve_id(self, packet_id: PacketID) -> None:
        if self._bitmap & (1 << packet_id):
            raise KeyError()
        self._bitmap |= 1 << packet_id
