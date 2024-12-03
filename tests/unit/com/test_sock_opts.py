import sys

import pytest
from pytest_mock import MockFixture

from mio_mqtt.com.sock_opts import _SocketOpts


def mock_import(
    name: str,
    item_in_fromlist: str,
) -> object:
    def inner_mock_import(
        inner_name: str,
        globals_: dict[str, object] | None = None,
        locals_: dict[str, object] | None = None,
        inner_fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if inner_name == name and item_in_fromlist in inner_fromlist:
            raise ImportError()
        return __import__(inner_name, globals_, locals_, inner_fromlist, level)

    return inner_mock_import


def mock_module(
    name: str,
) -> object:
    def inner_mock_import(
        inner_name: str,
        globals_: dict[str, object] | None = None,
        locals_: dict[str, object] | None = None,
        inner_fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if inner_name == name:
            raise ImportError()
        return __import__(inner_name, globals_, locals_, inner_fromlist, level)

    return inner_mock_import


class TestSocketOpts:
    def test_so_reuseaddr_ok(self, mocker: MockFixture) -> None:
        mocker.patch("socket.SO_REUSEADDR", 1)
        mocker.patch("socket.SOL_SOCKET", 2)
        result = _SocketOpts._so_reuseaddr()
        assert result == ((2, 1, 1),)

    def test_so_reuseaddr_fail(self, mocker: MockFixture) -> None:
        err_import = mock_import(
            name="socket", item_in_fromlist="SO_REUSEADDR"
        )
        mocker.patch("builtins.__import__", side_effect=err_import)
        with pytest.raises(ImportError):
            _SocketOpts._so_reuseaddr()

    def test_so_reuseport_ok(self, mocker: MockFixture) -> None:
        if sys.platform == "win32":
            assert True
        mocker.patch("socket.SO_REUSEPORT", 1)
        mocker.patch("socket.SOL_SOCKET", 2)
        result = _SocketOpts._so_reuseport()
        assert result == ((2, 1, 1),)

    def test_so_reuseport_fail(self, mocker: MockFixture) -> None:
        err_import = mock_import(
            name="socket", item_in_fromlist="SO_REUSEPORT"
        )
        mocker.patch("builtins.__import__", side_effect=err_import)
        with pytest.raises(ImportError):
            _SocketOpts._so_reuseport()

    def test_tcp_nodelay_ok(self, mocker: MockFixture) -> None:
        mocker.patch("socket.TCP_NODELAY", 1)
        mocker.patch("socket.IPPROTO_TCP", 2)
        result = _SocketOpts._tcp_nodelay()
        assert result == ((2, 1, 1),)

    def test_tcp_nodelay_fail(self, mocker: MockFixture) -> None:
        err_import = mock_import(name="socket", item_in_fromlist="TCP_NODELAY")
        mocker.patch("builtins.__import__", side_effect=err_import)
        with pytest.raises(ImportError):
            _SocketOpts._tcp_nodelay()

    def test_so_keepalive_ok(self, mocker: MockFixture) -> None:
        mocker.patch("socket.SO_KEEPALIVE", 1)
        mocker.patch("socket.SOL_SOCKET", 2)
        result = _SocketOpts._so_keepalive()
        expected = ((2, 1, 1),)
        assert result == expected

    def test_so_keepalive_fail(self, mocker: MockFixture) -> None:
        err_import = mock_module(
            name="socket",
        )
        mocker.patch("builtins.__import__", side_effect=err_import)
        with pytest.raises(ImportError):
            _SocketOpts._so_keepalive()

    def test_tcp_quickack_ok(self, mocker: MockFixture) -> None:
        if sys.platform != "linux":
            assert True
        mocker.patch("socket.TCP_QUICKACK", 1)
        mocker.patch("socket.IPPROTO_TCP", 2)
        result = _SocketOpts._tcp_quickack()
        assert result == ((2, 1, 1),)

    def test_tcp_quickack_fail(self, mocker: MockFixture) -> None:
        err_import = mock_import(
            name="socket", item_in_fromlist="TCP_QUICKACK"
        )
        mocker.patch("builtins.__import__", side_effect=err_import)
        with pytest.raises(ImportError):
            _SocketOpts._tcp_quickack()

    def test_so_lowat_ok(self, mocker: MockFixture) -> None:
        mocker.patch("socket.SO_RCVLOWAT", 1)
        mocker.patch("socket.SO_SNDLOWAT", 2)
        mocker.patch("socket.SOL_SOCKET", 3)
        result = _SocketOpts._so_lowat()
        assert result == ((3, 1, 1), (3, 2, 1))

    def test_so_lowat_fail(self, mocker: MockFixture) -> None:
        err_import = mock_import(name="socket", item_in_fromlist="SO_RCVLOWAT")
        mocker.patch("builtins.__import__", side_effect=err_import)
        with pytest.raises(ImportError):
            _SocketOpts._so_lowat()

    def test_gather_all_ok(self, mocker: MockFixture) -> None:
        mocker.patch.object(
            _SocketOpts, "_so_reuseaddr", return_value=((1, 2, 3),)
        )
        mocker.patch.object(
            _SocketOpts, "_so_reuseport", return_value=((4, 5, 6),)
        )
        mocker.patch.object(
            _SocketOpts, "_tcp_nodelay", return_value=((7, 8, 9),)
        )
        mocker.patch.object(
            _SocketOpts, "_so_keepalive", return_value=((10, 11, 12),)
        )
        mocker.patch.object(
            _SocketOpts, "_tcp_quickack", return_value=((13, 14, 15),)
        )
        mocker.patch.object(
            _SocketOpts, "_so_lowat", return_value=((16, 17, 18),)
        )
        result = _SocketOpts.gather_all()
        expected = (
            (1, 2, 3),
            (4, 5, 6),
            (7, 8, 9),
            (10, 11, 12),
            (13, 14, 15),
            (16, 17, 18),
        )
        assert result == expected

    def test_gather_all_fail_one(self, mocker: MockFixture) -> None:
        mocker.patch.object(
            _SocketOpts, "_so_reuseaddr", return_value=((1, 2, 3),)
        )
        mocker.patch.object(
            _SocketOpts, "_so_reuseport", return_value=((4, 5, 6),)
        )
        mocker.patch.object(
            _SocketOpts, "_tcp_nodelay", return_value=((7, 8, 9),)
        )
        mocker.patch.object(
            _SocketOpts, "_so_keepalive", return_value=((10, 11, 12),)
        )
        mocker.patch.object(
            _SocketOpts, "_tcp_quickack", return_value=((13, 14, 15),)
        )
        mocker.patch.object(_SocketOpts, "_so_lowat", side_effect=ImportError)
        result = _SocketOpts.gather_all()
        expected = (
            (1, 2, 3),
            (4, 5, 6),
            (7, 8, 9),
            (10, 11, 12),
            (13, 14, 15),
        )
        assert result == expected
