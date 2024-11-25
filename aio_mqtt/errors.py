from aio_mqtt.types import Slots

BASE_EXCEPTION = Exception


class AioMqttError(BASE_EXCEPTION):
    __slots__: Slots = tuple()
