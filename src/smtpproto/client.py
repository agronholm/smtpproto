from __future__ import annotations

import logging
import socket
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from functools import partial
from ssl import SSLContext
from types import TracebackType
from typing import Any, ContextManager, TypeVar
from warnings import warn

from anyio import (
    BrokenResourceError,
    aclose_forcefully,
    connect_tcp,
    fail_after,
)
from anyio.abc import AsyncResource, BlockingPortal, SocketStream
from anyio.from_thread import start_blocking_portal
from anyio.streams.tls import TLSStream

from .auth import SMTPAuthenticator
from .protocol import ClientState, SMTPClientProtocol, SMTPException, SMTPResponse

logger: logging.Logger = logging.getLogger(__name__)
TAsync = TypeVar("TAsync", bound="AsyncSMTPClient")
TSync = TypeVar("TSync", bound="SyncSMTPClient")


@dataclass
class AsyncSMTPClient(AsyncResource):
    """
    An asynchronous SMTP client.

    This runs on asyncio or any other backend supported by AnyIO.

    It is recommended that this client is used as an async context manager instead of
    manually calling :meth:`~connect` and :meth:`aclose`, if possible.

    :param host: host name or IP address of the SMTP server
    :param port: port on the SMTP server to connect to
    :param connect_timeout: connection timeout (in seconds)
    :param timeout: timeout for sending requests and reading responses (in seconds)
    :param domain: domain name to send to the server as part of the greeting message
    :param ssl_context: SSL context to use for establishing TLS encrypted sessions
    :param authenticator: authenticator to use for authenticating with the SMTP server
    """

    host: str
    port: int = 587
    connect_timeout: float = 30
    timeout: float = 60
    domain: str = field(default_factory=socket.gethostname)
    ssl_context: SSLContext | None = None
    authenticator: SMTPAuthenticator | None = None
    _protocol: SMTPClientProtocol = field(
        init=False, default_factory=SMTPClientProtocol
    )
    _stream: TLSStream | SocketStream | None = field(init=False, default=None)

    async def __aenter__(self: TAsync) -> TAsync:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __del__(self) -> None:
        if self._stream:
            warn(
                f"unclosed {self.__class__.__name__}",
                ResourceWarning,
                stacklevel=1,
                source=self._stream,
            )

    async def connect(self) -> None:
        """Connect to the SMTP server."""
        if not self._stream:
            with fail_after(self.connect_timeout):
                self._stream = await connect_tcp(self.host, self.port)

            try:
                await self._wait_response()
                await self._send_command(self._protocol.send_greeting, self.domain)

                # Do the TLS handshake if supported by the server
                if "STARTTLS" in self._protocol.extensions:
                    await self._send_command(self._protocol.start_tls)
                    self._stream = await TLSStream.wrap(
                        self._stream,
                        hostname=self.host,
                        ssl_context=self.ssl_context,
                        standard_compatible=False,
                    )

                    # Send a new EHLO command to determine new capabilities
                    await self._send_command(self._protocol.send_greeting, self.domain)

                # Use the authenticator if one was provided
                if self.authenticator:
                    auth_gen = self.authenticator.authenticate()
                    try:
                        auth_data = await auth_gen.__anext__()
                        response = await self._send_command(
                            self._protocol.authenticate,
                            self.authenticator.mechanism,
                            auth_data,
                        )
                        while self._protocol.state is ClientState.authenticating:
                            auth_data = await auth_gen.asend(response.message)
                            self._protocol.send_authentication_data(auth_data)
                            await self._flush_output()
                    except StopAsyncIteration:
                        pass
                    finally:
                        await auth_gen.aclose()
            except BaseException:
                await aclose_forcefully(self)
                self._stream = None
                raise

    async def aclose(self) -> None:
        """Close the connection, if connected."""
        if self._stream:
            try:
                if self._protocol.state is not ClientState.finished:
                    await self._send_command(self._protocol.quit)
            finally:
                await self._stream.aclose()
                self._stream = None

    async def _wait_response(self) -> SMTPResponse:
        while True:
            if not self._stream:
                raise SMTPException("Not connected")

            if self._protocol.needs_incoming_data:
                try:
                    with fail_after(self.timeout):
                        data = await self._stream.receive()
                except (BrokenResourceError, TimeoutError):
                    await aclose_forcefully(self._stream)
                    self._stream = None
                    raise

                logger.debug("Received: %s", data)
                response = self._protocol.feed_bytes(data)
                if response:
                    if response.is_error():
                        response.raise_as_exception()
                    else:
                        return response

                await self._flush_output()

    async def _flush_output(self) -> None:
        if not self._stream:
            raise SMTPException("Not connected")

        data = self._protocol.get_outgoing_data()
        if data:
            logger.debug("Sent: %s", data)
            try:
                with fail_after(self.timeout):
                    await self._stream.send(data)
            except (BrokenResourceError, TimeoutError):
                await aclose_forcefully(self._stream)
                self._stream = None
                raise

    async def _send_command(self, command: Callable, *args) -> SMTPResponse:
        if not self._stream:
            raise SMTPException("Not connected")

        command(*args)
        await self._flush_output()
        return await self._wait_response()

    async def send_message(
        self,
        message: EmailMessage,
        *,
        sender: str | Address | None = None,
        recipients: Iterable[str] | None = None,
    ) -> SMTPResponse:
        sender = sender or parseaddr(message.get("From"))[1]
        await self._send_command(self._protocol.mail, sender)

        if not recipients:
            tos: list[str] = message.get_all("to", [])
            ccs: list[str] = message.get_all("cc", [])
            resent_tos: list[str] = message.get_all("resent-to", [])
            resent_ccs: list[str] = message.get_all("resent-cc", [])
            recipients = [
                email
                for name, email in getaddresses(tos + ccs + resent_tos + resent_ccs)
            ]

        for recipient in recipients:
            await self._send_command(self._protocol.recipient, recipient)

        await self._send_command(self._protocol.start_data)
        return await self._send_command(self._protocol.data, message)


class SyncSMTPClient:
    """
    A synchronous (blocking) SMTP client.

    It is recommended that this client is used as a context manager instead of manually
    calling :meth:`~connect` and :meth:`close`, if possible.

    :param host: host name or IP address of the SMTP server
    :param port: port on the SMTP server to connect to
    :param connect_timeout: connection timeout (in seconds)
    :param timeout: timeout for sending requests and reading responses (in seconds)
    :param domain: domain name to send to the server as part of the greeting message
    :param ssl_context: SSL context to use for establishing TLS encrypted sessions
    :param authenticator: authenticator to use for authenticating with the SMTP server
    :param async_backend: name of the AnyIO-supported asynchronous backend
    :param async_backend_options: dictionary of keyword arguments passed to
        :func:`anyio.from_thread.start_blocking_portal`
    """

    _portal_cm: ContextManager[BlockingPortal] | None = None
    _portal: BlockingPortal | None = None

    def __init__(
        self,
        *args: Any,
        async_backend: str = "asyncio",
        async_backend_options: dict[str, Any] | None = None,
        **kwargs: Any,
    ):
        self._async_backend = async_backend
        self._async_backend_options = async_backend_options
        self._async_client = AsyncSMTPClient(*args, **kwargs)

    def __enter__(self: TSync) -> TSync:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        if self._portal:
            warn(
                f"unclosed {self.__class__.__name__}",
                ResourceWarning,
                stacklevel=1,
                source=self._portal,
            )
            self.close()

    def connect(self) -> None:
        """Connect to the SMTP server."""
        portal_cm = start_blocking_portal(
            self._async_backend, self._async_backend_options
        )
        portal = portal_cm.__enter__()
        try:
            portal.call(self._async_client.connect)
        except BaseException:
            portal_cm.__exit__(*sys.exc_info())
            raise

        self._portal_cm = portal_cm
        self._portal = portal

    def close(self) -> None:
        """Close the connection, if connected."""
        if self._portal:
            try:
                self._portal.call(self._async_client.aclose)
            finally:
                del self._portal
                if self._portal_cm:
                    self._portal_cm.__exit__(None, None, None)
                    del self._portal_cm

    def send_message(
        self,
        message: EmailMessage,
        *,
        sender: str | Address | None = None,
        recipients: Iterable[str] | None = None,
    ) -> SMTPResponse:
        if not self._portal:
            raise SMTPException("Not connected")

        func = partial(
            self._async_client.send_message, sender=sender, recipients=recipients
        )
        return self._portal.call(func, message)
