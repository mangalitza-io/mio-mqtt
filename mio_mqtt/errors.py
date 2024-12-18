from ipaddress import AddressValueError

from mio_mqtt.types import Slots

BASE_EXCEPTION = Exception


class AioMqttError(BASE_EXCEPTION):
    __slots__: Slots = tuple()


class InvalidAddress(AioMqttError, AddressValueError, OSError):
    __slots__: Slots = tuple()
