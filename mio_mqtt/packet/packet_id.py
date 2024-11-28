from typing import TypeAlias

from mio_mqtt.types import All, Slots

__all__: All = (
    "PacketID",
    "PacketIdentifier",
)

PacketID: TypeAlias = int


class PacketIdentifier:
    # TODO OPTIMIZE
    #  Temporary solution from wialon gmqtt
    MAX: int = 0xF
    __slots__: Slots = (
        "_used_ids",
        "_last_used_id",
        "_max_plus_one",
    )

    def __init__(self) -> None:
        self._used_ids: set[PacketID] = set()
        self._last_used_id: PacketID = 0
        self._max_plus_one: int = self.MAX + 1

    def get_id(self) -> PacketID:
        if self.MAX == len(self._used_ids):
            raise OverflowError()
        while True:
            self._last_used_id = (self._last_used_id + 1) % self._max_plus_one

            if self._last_used_id not in self._used_ids:
                self._used_ids.add(self._last_used_id)
                return self._last_used_id

    def release_id(self, packet_id: PacketID) -> None:
        try:
            return self._used_ids.remove(packet_id)
        except KeyError:
            return None
