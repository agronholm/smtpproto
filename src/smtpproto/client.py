from __future__ import annotations

import logging
import socket
import sys
from collections.abc import AsyncGenerator, Callable, Generator, Iterable
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from ssl import SSLContext
from types import TracebackType
from typing import Any, TypeVar, cast
from warnings import warn

from anyio import (
    BrokenResourceError,
    Semaphore,
    aclose_forcefully,
    connect_tcp,
    fail_after,
    move_on_after,
)
from anyio.abc import BlockingPortal, SocketStream
from anyio.from_thread import BlockingPortalProvider
from anyio.streams.tls import TLSStream

from .auth import SMTPAuthenticator
from .protocol import ClientState, SMTPClientProtocol, SMTPResponse

if sys.version_info >= (3, 10):
    from typing import ParamSpec
else:
    from typing_extensions import ParamSpec

logger: logging.Logger = logging.getLogger(__name__)
P = ParamSpec("P")
TAsync = TypeVar("TAsync", bound="AsyncSMTPClient")
TSync = TypeVar("TSync", bound="SyncSMTPClient")


@dataclass
class AsyncSMTPSession:
    """
    Encapsulates a live connection to an SMTP server.

    :ivar SMTPClientProtocol protocol: the protocol state machine
    """

    host: str
    port: int
    connect_timeout: float
    timeout: float
    domain: str
    authenticator: SMTPAuthenticator | None
    ssl_context: SSLContext | None
    protocol: SMTPClientProtocol = field(init=False, default_factory=SMTPClientProtocol)
    _stream: TLSStream | SocketStream = field(init=False)
    _exit_stack: AsyncExitStack = field(init=False)

    async def send_message(
        self,
        message: EmailMessage,
        *,
        sender: str | Address | None = None,
        recipients: Iterable[str] | None = None,
    ) -> SMTPResponse:
        """
        Send an email message.

        :param message: the message to send
        :param sender: override the sender address in the ``MAIL FROM`` command
        :param recipients: override the destination addresses in the ``RCPT TO``
            commands
        :return: the SMTP response

        """
        # type checkers don't handle default typevar values yet, so they see
        # message.get() returning Any | None thought it should be str
        from_ = cast(str, message.get("From"))
        sender = sender or parseaddr(from_)[1]
        await self.send_command(self.protocol.mail, sender)

        if not recipients:
            tos: list[str] = message.get_all("to", [])
            ccs: list[str] = message.get_all("cc", [])
            bccs: list[str] = message.get_all("bcc", [])
            resent_tos: list[str] = message.get_all("resent-to", [])
            resent_ccs: list[str] = message.get_all("resent-cc", [])
            resent_bccs: list[str] = message.get_all("resent-bcc", [])
            recipients = [
                email
                for name, email in getaddresses(
                    tos + ccs + bccs + resent_tos + resent_ccs + resent_bccs
                )
            ]

        for recipient in recipients:
            await self.send_command(self.protocol.recipient, recipient)

        await self.send_command(self.protocol.start_data)
        return await self.send_command(self.protocol.data, message)

    async def send_command(
        self, command: Callable[P, None], /, *args: P.args, **kwargs: P.kwargs
    ) -> SMTPResponse:
        """
        Send a command to the SMTP server and return the response.

        :param command: a callable from :class:`~.protocol.SMTPClientProtocol`
        :param args: positional arguments to ``command``
        :param kwargs: keyword arguments to ``command``

        """
        command(*args, **kwargs)
        await self._flush_output()
        return await self._wait_response()

    async def _wait_response(self) -> SMTPResponse:
        while True:
            if self.protocol.needs_incoming_data:
                try:
                    with fail_after(self.timeout):
                        data = await self._stream.receive()
                except (BrokenResourceError, TimeoutError):
                    await aclose_forcefully(self._stream)
                    del self._stream
                    raise

                logger.debug("Received: %s", data)
                response = self.protocol.feed_bytes(data)
                if response:
                    if response.is_error():
                        response.raise_as_exception()
                    else:
                        return response

                await self._flush_output()

    async def _flush_output(self) -> None:
        data = self.protocol.get_outgoing_data()
        if data:
            logger.debug("Sent: %s", data)
            try:
                with fail_after(self.timeout):
                    await self._stream.send(data)
            except (BrokenResourceError, TimeoutError):
                await aclose_forcefully(self._stream)
                del self._stream
                raise

    async def aclose(self) -> None:
        if hasattr(self, "_stream"):
            stream = self._stream
            del self._stream
            with move_on_after(5, shield=True):
                await stream.aclose()

    async def __aenter__(self) -> AsyncSMTPSession:
        with fail_after(self.connect_timeout):
            self._stream = await connect_tcp(self.host, self.port)

        async with AsyncExitStack() as exit_stack:
            exit_stack.push_async_callback(self.aclose)

            await self._wait_response()
            await self.send_command(self.protocol.send_greeting, self.domain)

            # Do the TLS handshake if supported by the server
            if "STARTTLS" in self.protocol.extensions:
                await self.send_command(self.protocol.start_tls)
                self._stream = await TLSStream.wrap(
                    self._stream,
                    hostname=self.host,
                    ssl_context=self.ssl_context,
                    standard_compatible=False,
                )

                # Send a new EHLO command to determine new capabilities
                await self.send_command(self.protocol.send_greeting, self.domain)

            # Use the authenticator if one was provided
            if self.authenticator:
                auth_gen = self.authenticator.authenticate()
                try:
                    auth_data = await auth_gen.__anext__()
                    response = await self.send_command(
                        self.protocol.authenticate,
                        self.authenticator.mechanism,
                        auth_data,
                    )
                    while self.protocol.state is ClientState.authenticating:
                        auth_data = await auth_gen.asend(response.message)
                        self.protocol.send_authentication_data(auth_data)
                        await self._flush_output()
                except StopAsyncIteration:
                    pass
                finally:
                    await auth_gen.aclose()

            self._exit_stack = exit_stack.pop_all()

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        try:
            if self.protocol.state is not ClientState.finished:
                await self.send_command(self.protocol.quit)
        finally:
            await self._exit_stack.__aexit__(exc_type, exc_val, exc_tb)

    def __del__(self) -> None:
        if hasattr(self, "_stream"):
            warn(
                f"unclosed {self.__class__.__name__}",
                ResourceWarning,
                stacklevel=1,
                source=self,
            )


class AsyncSMTPClient:
    """
    An asynchronous SMTP client.

    This runs on asyncio or any other backend supported by AnyIO.

    :param host: host name or IP address of the SMTP server
    :param port: port on the SMTP server to connect to
    :param connect_timeout: connection timeout (in seconds)
    :param timeout: timeout for sending requests and reading responses (in seconds)
    :param domain: domain name to send to the server as part of the greeting message
    :param ssl_context: SSL context to use for establishing TLS encrypted sessions
    :param authenticator: authenticator to use for authenticating with the SMTP server
    :param max_concurrent_connections: maximum number of connections to allows to the
        SMTP server before blocking
    """

    def __init__(
        self,
        host: str,
        port: int = 587,
        connect_timeout: float = 30,
        timeout: float = 60,
        domain: str | None = None,
        ssl_context: SSLContext | None = None,
        authenticator: SMTPAuthenticator | None = None,
        max_concurrent_connections: int = 50,
    ):
        self.host = host
        self.port = port
        self.connect_timeout = connect_timeout
        self.timeout = timeout
        self.domain: str = domain or socket.gethostname()
        self.ssl_context = ssl_context
        self.authenticator = authenticator
        self._semaphore = Semaphore(max_concurrent_connections)

    @asynccontextmanager
    async def connect(self) -> AsyncGenerator[AsyncSMTPSession, Any]:
        """
        Establish a session with the SMTP server.

        The returned async context manager connects to the SMTP server and performs the
        protocol handshake. After that, it optionally establishes an encrypted session
        with ``STARTTLS``, and then logs in (if an authenticator was provided).

        :return: a context manager yielding an :class:`AsyncSMTPSession`

        """
        async with self._semaphore:
            session = AsyncSMTPSession(
                self.host,
                self.port,
                self.connect_timeout,
                self.timeout,
                self.domain,
                self.authenticator,
                self.ssl_context,
            )
            async with session:
                yield session

    async def send_message(
        self,
        message: EmailMessage,
        *,
        sender: str | Address | None = None,
        recipients: Iterable[str] | None = None,
    ) -> SMTPResponse:
        """
        Open a session with the SMTP server, send an email and then close the session.

        This is a convenience method for the following::

            async with client.connect() as session:
                return await session.send_message(message, sender=sender, \
recipients=recipients)

        :param message: the message to send
        :param sender: override the sender address in the ``MAIL FROM`` command
        :param recipients: override the destination addresses in the ``RCPT TO``
            commands
        :return: the SMTP response

        """
        async with self.connect() as session:
            return await session.send_message(
                message, sender=sender, recipients=recipients
            )


@dataclass
class SyncSMTPSession:
    portal: BlockingPortal
    async_session: AsyncSMTPSession

    def send_command(
        self, command: Callable[P, None], /, *args: P.args, **kwargs: P.kwargs
    ) -> SMTPResponse:
        """
        Send a command to the SMTP server and return the response.

        :param command: a callable from :class:`~.protocol.SMTPClientProtocol`
        :param args: positional arguments to ``command``
        :param kwargs: keyword arguments to ``command``

        """
        return self.portal.call(
            lambda: self.async_session.send_command(command, *args, **kwargs)
        )

    def send_message(
        self,
        message: EmailMessage,
        *,
        sender: str | Address | None = None,
        recipients: Iterable[str] | None = None,
    ) -> SMTPResponse:
        """
        Send an email message.

        :param message: the message to send
        :param sender: override the sender address in the ``MAIL FROM`` command
        :param recipients: override the destination addresses in the ``RCPT TO``
            commands
        :return: the SMTP response

        """
        return self.portal.call(
            lambda: self.async_session.send_message(
                message, sender=sender, recipients=recipients
            )
        )


class SyncSMTPClient:
    """
    A synchronous (blocking) SMTP client.

    :param host: host name or IP address of the SMTP server
    :param port: port on the SMTP server to connect to
    :param connect_timeout: connection timeout (in seconds)
    :param timeout: timeout for sending requests and reading responses (in seconds)
    :param domain: domain name to send to the server as part of the greeting message
    :param ssl_context: SSL context to use for establishing TLS encrypted sessions
    :param authenticator: authenticator to use for authenticating with the SMTP server
    :param max_concurrent_connections: maximum number of connections to allows to the
        SMTP server before blocking
    :param async_backend: name of the AnyIO-supported asynchronous backend
    :param async_backend_options: dictionary of keyword arguments passed to
        :func:`anyio.from_thread.start_blocking_portal`
    """

    def __init__(
        self,
        host: str,
        port: int = 587,
        connect_timeout: float = 30,
        timeout: float = 60,
        domain: str | None = None,
        ssl_context: SSLContext | None = None,
        authenticator: SMTPAuthenticator | None = None,
        max_concurrent_connections: int = 50,
        async_backend: str = "asyncio",
        async_backend_options: dict[str, Any] | None = None,
    ):
        self._async_client = AsyncSMTPClient(
            host=host,
            port=port,
            connect_timeout=connect_timeout,
            timeout=timeout,
            domain=domain or socket.gethostname(),
            ssl_context=ssl_context,
            authenticator=authenticator,
            max_concurrent_connections=max_concurrent_connections,
        )
        self._portal_provider = BlockingPortalProvider(
            async_backend, async_backend_options
        )

    @contextmanager
    def connect(self) -> Generator[SyncSMTPSession, Any, None]:
        """
        Establish a session with the SMTP server.

        The returned context manager connects to the SMTP server and performs the
        protocol handshake. After that, it optionally establishes an encrypted session
        with ``STARTTLS``, and then logs in (if an authenticator was provided).

        :return: a context manager yielding a :class:`SyncSMTPSession`

        """
        with self._portal_provider as portal:
            async_session_cm = portal.call(self._async_client.connect)
            with portal.wrap_async_context_manager(async_session_cm) as async_session:
                yield SyncSMTPSession(portal, async_session)

    def send_message(
        self,
        message: EmailMessage,
        *,
        sender: str | Address | None = None,
        recipients: Iterable[str] | None = None,
    ) -> SMTPResponse:
        """
        Open a session with the SMTP server, send an email and then close the session.

        This is a convenience method for the following::

            with client.connect() as session:
                return session.send_message(message, sender=sender, \
recipients=recipients)

        :param message: the message to send
        :param sender: override the sender address in the ``MAIL FROM`` command
        :param recipients: override the destination addresses in the ``RCPT TO``
            commands
        :return: the SMTP response

        """
        with self.connect() as session:
            return session.send_message(message, sender=sender, recipients=recipients)
