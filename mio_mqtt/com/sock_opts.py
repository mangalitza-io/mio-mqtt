# mypy: disable-error-code="unused-ignore, attr-defined, misc"
from collections.abc import Callable

from mio_mqtt.types import All, SockOpts

__all__: All = ("_SocketOpts",)


class _SocketOpts:
    @classmethod
    def gather_all(cls) -> SockOpts:
        sock_opts_funcs: tuple[Callable[[], SockOpts], ...] = (
            cls._so_reuseaddr,
            cls._so_reuseport,
            cls._tcp_nodelay,
            cls._so_keepalive,
            cls._tcp_quickack,
            cls._so_lowat,
        )
        sock_opts: SockOpts = tuple()
        for sock_opts_func in sock_opts_funcs:
            try:
                sock_opts = sock_opts + sock_opts_func()
            except ImportError:
                continue
        return sock_opts

    @staticmethod
    def _so_reuseaddr() -> SockOpts:
        try:
            from socket import SO_REUSEADDR, SOL_SOCKET
        except ImportError:
            raise ImportError()
        return ((SOL_SOCKET, SO_REUSEADDR, 1),)

    @staticmethod
    def _so_reuseport() -> SockOpts:
        try:
            from socket import SO_REUSEPORT, SOL_SOCKET
        except ImportError:
            raise ImportError()
        return ((SOL_SOCKET, SO_REUSEPORT, 1),)

    @staticmethod
    def _tcp_nodelay() -> SockOpts:
        try:
            from socket import IPPROTO_TCP, TCP_NODELAY
        except ImportError:
            raise ImportError()
        return ((IPPROTO_TCP, TCP_NODELAY, 1),)

    @staticmethod
    def _so_keepalive() -> SockOpts:
        try:
            from socket import SO_KEEPALIVE, SOL_SOCKET
        except ImportError:
            raise ImportError()
        return ((SOL_SOCKET, SO_KEEPALIVE, 1),)

    @staticmethod
    def _tcp_quickack() -> SockOpts:
        try:
            from socket import IPPROTO_TCP, TCP_QUICKACK
        except ImportError:
            raise ImportError()
        return ((IPPROTO_TCP, TCP_QUICKACK, 1),)

    @staticmethod
    def _so_lowat() -> SockOpts:
        try:
            from socket import SO_RCVLOWAT, SO_SNDLOWAT, SOL_SOCKET
        except ImportError:
            raise ImportError()
        return (
            (SOL_SOCKET, SO_RCVLOWAT, 1),
            (SOL_SOCKET, SO_SNDLOWAT, 1),
        )
