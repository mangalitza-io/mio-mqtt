from mio_mqtt.routing import RadixTrieRouter


class TestRadixTrie:
    result_1: str
    result_2: str
    result_3: str

    @classmethod
    def setup_class(cls) -> None:
        cls.result_1 = "result 1"
        cls.result_2 = "result 2"
        cls.result_3 = "result 3"

    def setup_method(self) -> None:
        self.trie: RadixTrieRouter[str] = RadixTrieRouter()

    def test_insert_and_exact_match(self) -> None:
        topic: str = "home/kitchen/light"

        self.trie.insert(topic=topic, item=self.result_1)
        handlers: list[str] = self.trie.match(topic=topic)
        assert len(handlers) == 1
        assert handlers[0] == self.result_1

    def test_single_level_wildcard(self) -> None:
        src_topic: str = "home/+/light"
        out_topic: str = "home/kitchen/light"

        self.trie.insert(topic=src_topic, item=self.result_1)
        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 1
        assert handlers[0] == self.result_1

    def test_multi_level_wildcard(self) -> None:
        src_topic: str = "home/#"
        out_topic: str = "home/kitchen/light"

        self.trie.insert(topic=src_topic, item=self.result_1)
        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 1
        assert handlers[0] == self.result_1

    def test_combined_wildcards(self) -> None:
        src_1_topic: str = "home/#"
        src_2_topic: str = "home/+/light"
        out_topic: str = "home/kitchen/light"

        self.trie.insert(topic=src_1_topic, item=self.result_1)
        self.trie.insert(topic=src_2_topic, item=self.result_2)
        handlers = self.trie.match(out_topic)
        assert len(handlers) == 2
        assert handlers[0] == self.result_1
        assert handlers[1] == self.result_2

    def test_no_match(self) -> None:
        src_topic: str = "home/garage/door"
        out_topic: str = "home/kitchen/light"

        self.trie.insert(topic=src_topic, item=self.result_1)
        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 0

    def test_partial_match_no_wildcard(self) -> None:
        src_topic: str = "home/kitchen/light/brightness"
        out_topic: str = "home/kitchen/light"

        self.trie.insert(topic=src_topic, item=self.result_1)
        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 0

    def test_empty_trie(self) -> None:
        out_topic: str = "home/kitchen/light"

        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 0

    def test_multiple_wildcards(self) -> None:
        src_topic: str = "+/kitchen/#"
        out_topic: str = "home/kitchen/light"

        self.trie.insert(topic=src_topic, item=self.result_1)
        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 1
        assert handlers[0] == self.result_1

    def test_overlapping_wildcards_and_exact(self) -> None:
        src_1_topic: str = "home/kitchen/light"
        src_2_topic: str = "home/kitchen/+"
        out_topic: str = "home/kitchen/light"

        self.trie.insert(src_1_topic, item=self.result_1)
        self.trie.insert(src_2_topic, item=self.result_2)
        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 2
        assert handlers[0] == self.result_1
        assert handlers[1] == self.result_2

    def test_nested_topics(self) -> None:
        src_1_topic: str = "home/kitchen/light"
        src_2_topic: str = "home/+/temperature"
        src_3_topic: str = "home/kitchen/temperature"
        out_topic: str = "home/kitchen/temperature"

        self.trie.insert(src_1_topic, item=self.result_1)
        self.trie.insert(src_2_topic, item=self.result_2)
        self.trie.insert(src_3_topic, item=self.result_3)

        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 2
        assert handlers[0] == self.result_3
        assert handlers[1] == self.result_2

    def test_subtree_match(self) -> None:
        src_1_topic: str = "home/kitchen/#"
        src_2_topic: str = "home/kitchen/light"
        out_topic: str = "home/kitchen/light"

        self.trie.insert(src_1_topic, item=self.result_1)
        self.trie.insert(src_2_topic, item=self.result_2)
        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 2
        assert handlers[0] == self.result_1
        assert handlers[1] == self.result_2

    def test_non_existent_wildcard(self) -> None:
        src_topic: str = "office/#"
        out_topic: str = "home/kitchen/light"

        self.trie.insert(topic=src_topic, item=self.result_1)
        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 0

    def test_all_topics_wildcard(self) -> None:
        src_topic: str = "#"
        out_topic: str = "home/kitchen/light"

        self.trie.insert(topic=src_topic, item=self.result_1)
        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 1
        assert handlers[0] == self.result_1

    def test_multiple_matches_same_topic(self) -> None:
        src_1_topic: str = "home/kitchen/light"
        src_2_topic: str = "home/kitchen/light"
        out_topic: str = "home/kitchen/light"

        self.trie.insert(src_1_topic, item=self.result_1)
        self.trie.insert(src_2_topic, item=self.result_2)
        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 2
        assert handlers[0] == self.result_1
        assert handlers[1] == self.result_2

    def test_trie_with_conflicting_wildcards(self) -> None:
        src_1_topic: str = "home/kitchen/+/light"
        src_2_topic: str = "home/kitchen/light"
        out_topic: str = "home/kitchen/room/light"

        self.trie.insert(src_1_topic, item=self.result_1)
        self.trie.insert(src_2_topic, item=self.result_2)
        handlers: list[str] = self.trie.match(out_topic)
        assert len(handlers) == 1
        assert handlers[0] == self.result_1