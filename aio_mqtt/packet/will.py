from aio_mqtt.types import DictStrObject

from .codec import encode_string


class WillMessage:
    ALLOWED_QOS: set[int] = {0, 1, 2}

    def __init__(
        self,
        topic: str,
        message: str,
        qos: int = 0,
        retain: bool = False,
        properties: DictStrObject | None = None,
    ) -> None:
        self.topic: str = topic
        self.message: str = message
        self.qos: int = qos
        self.retain: bool = retain
        self.properties: DictStrObject

        if properties is None:
            self.properties = {}
        else:
            self.properties = properties

        if self.qos not in self.ALLOWED_QOS:
            raise ValueError()

    @property
    def b_topic(self) -> bytes:
        return encode_string(self.topic)

    @property
    def b_message(self) -> bytes:
        return encode_string(self.message)
