import pytest

from mio_mqtt.packet.codec import StrCodec
from mio_mqtt.packet.sub_packet import Subscription, WillMessage


class TestWillMessage:
    will: WillMessage

    @classmethod
    def setup_class(cls) -> None:
        cls.will = WillMessage(
            topic="test/topic",
            message="Test Message",
            qos=1,
            retain=True,
            properties={},
        )

    def test_will_message_initialization(self) -> None:
        assert self.will.topic == "test/topic"
        assert self.will.message == "Test Message"
        assert self.will.qos == 1
        assert self.will.retain is True
        assert self.will.properties == {}

    def test_will_message_invalid_qos(self) -> None:
        with pytest.raises(ValueError):
            WillMessage(topic="test/topic", message="Test Message", qos=3)

    def test_will_message_b_properties(self) -> None:
        assert isinstance(self.will.b_properties, bytearray)

    def test_will_message_b_topic(self) -> None:
        encoded_topic = self.will.b_topic
        assert isinstance(encoded_topic, bytearray)
        _, topic = StrCodec.decode(encoded_topic)
        assert topic == "test/topic"

    def test_will_message_b_message(self) -> None:
        encoded_message = self.will.b_message
        assert isinstance(encoded_message, bytearray)
        _, topic = StrCodec.decode(encoded_message)
        assert topic == "Test Message"


class TestSubscription:
    subscription: Subscription

    @classmethod
    def setup_class(cls) -> None:
        cls.subscription = Subscription(
            topic="test/topic",
            qos=1,
            no_local=True,
            retain_as_published=False,
            retain_handling=2,
        )

    def test_subscription_initialization(self) -> None:
        assert self.subscription._topic == "test/topic"
        assert self.subscription._qos == 1
        assert self.subscription._no_local is True
        assert self.subscription._retain_as_published is False
        assert self.subscription._retain_handling == 2

    def test_subscription_to_bytes(self) -> None:
        serialized = self.subscription.to_bytes()
        assert isinstance(serialized, bytearray)

        deserialized_len, deserialized_subscription = Subscription.from_bytes(
            serialized
        )
        assert deserialized_subscription._topic == "test/topic"
        assert deserialized_subscription._qos == 1
        assert deserialized_subscription._no_local is True
        assert deserialized_subscription._retain_as_published is False
        assert deserialized_subscription._retain_handling == 2

    def test_subscription_from_bytes(self) -> None:
        data = bytearray()
        data.extend(StrCodec.encode("test/topic"))
        subscription_options = 0b00100101
        data.append(subscription_options)

        length, subscription = Subscription.from_bytes(data)
        assert subscription._topic == "test/topic"
        assert subscription._qos == 1
        assert subscription._no_local is True
        assert subscription._retain_as_published is False
        assert subscription._retain_handling == 2
