from abc import ABCMeta, abstractmethod
from asyncio import (
    AbstractEventLoop,
    Protocol,
    StreamReader,
    StreamReaderProtocol,
    StreamWriter,
    Transport,
)
from collections.abc import Callable
from socket import AddressFamily, SocketKind, socket
from typing import TypeAlias

from aio_mqtt.types import Address, Slots, SockOpts

ProtocolFactory: TypeAlias = Callable[[], Protocol]


class _TcpSocket(socket, metaclass=ABCMeta):
    FAMILY: AddressFamily
    TYPE: SocketKind = SocketKind.SOCK_STREAM
    PROTO: int = 0

    SOCK_OPTS: SockOpts = tuple()

    try:
        from socket import SOL_SOCKET
    except ImportError:
        pass
    else:
        try:
            from socket import SO_REUSEADDR
        except ImportError:
            pass
        else:
            SOCK_OPTS = SOCK_OPTS + ((SOL_SOCKET, SO_REUSEADDR, 1),)

        try:
            from socket import SO_REUSEPORT
        except ImportError:
            pass
        else:
            SOCK_OPTS = SOCK_OPTS + ((SOL_SOCKET, SO_REUSEPORT, 1),)

    try:
        from socket import IPPROTO_TCP
    except ImportError:
        pass
    else:
        try:
            from socket import TCP_NODELAY
        except ImportError:
            pass
        else:
            SOCK_OPTS = SOCK_OPTS + ((IPPROTO_TCP, TCP_NODELAY, 1),)

    __slots__: Slots = tuple()

    def __init__(self) -> None:
        super().__init__(family=self.FAMILY, type=self.TYPE, proto=self.PROTO)

        for sock_opt in self.SOCK_OPTS:
            try:
                self.setsockopt(*sock_opt)
            except (ValueError, TypeError):
                raise OSError()

    async def connect_async(
        self, __address: Address, loop: AbstractEventLoop
    ) -> None:
        return await loop.sock_connect(self, __address)

    @abstractmethod
    async def create_connection(
        self,
        address: Address,
        protocol_factory: ProtocolFactory,
        loop: AbstractEventLoop,
        **kwargs: object,
    ) -> tuple[Transport, Protocol]:
        raise NotImplementedError()

    async def create_stream_connection(
        self,
        address: Address,
        loop: AbstractEventLoop,
    ) -> tuple[StreamReader, StreamWriter]:
        reader: StreamReader = StreamReader(loop=loop)
        protocol: StreamReaderProtocol = StreamReaderProtocol(
            stream_reader=reader, client_connected_cb=None, loop=loop
        )
        transport, _ = await self.create_connection(
            address=address, protocol_factory=lambda: protocol, loop=loop
        )
        writer: StreamWriter = StreamWriter(
            transport=transport, protocol=protocol, reader=reader, loop=loop
        )
        return reader, writer


class _TcpIPSocket(_TcpSocket, metaclass=ABCMeta):
    async def create_connection(
        self,
        address: Address,
        protocol_factory: ProtocolFactory,
        loop: AbstractEventLoop,
        **kwargs: object,
    ) -> tuple[Transport, Protocol]:
        await self.connect_async(address, loop=loop)
        return await loop.create_connection(
            protocol_factory=protocol_factory,
            host=None,
            port=None,
            ssl=None,
            family=0,
            proto=0,
            flags=0,
            sock=self,
            local_addr=None,
            server_hostname=None,
            ssl_handshake_timeout=None,
            happy_eyeballs_delay=None,
            interleave=None,
        )


class TCPInetSocket(_TcpIPSocket):
    FAMILY: AddressFamily = AddressFamily.AF_INET
    __slots__: Slots = tuple()


class TCPInet6Socket(_TcpIPSocket):
    FAMILY: AddressFamily = AddressFamily.AF_INET6
    __slots__: Slots = tuple()


class TCPUnixSocket(_TcpSocket):
    FAMILY: AddressFamily = AddressFamily.AF_UNIX
    __slots__: Slots = tuple()

    async def create_connection(
        self,
        address: Address,
        protocol_factory: ProtocolFactory,
        loop: AbstractEventLoop,
        **kwargs: object,
    ) -> tuple[Transport, Protocol]:
        await self.connect_async(address, loop=loop)
        return await loop.create_unix_connection(
            protocol_factory=protocol_factory,
            path=None,
            ssl=None,
            sock=self,
            server_hostname=None,
            ssl_handshake_timeout=None,
        )
