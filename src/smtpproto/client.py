import logging
import socket
from dataclasses import dataclass, field
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from functools import partial
from ssl import SSLContext
from typing import Optional, Iterable, Callable, Union, List, Dict, Any

from anyio import (
    connect_tcp, fail_after, maybe_async_cm, start_blocking_portal, aclose_forcefully,
    BrokenResourceError)
from anyio.abc import SocketStream, BlockingPortal, AsyncResource
from anyio.streams.tls import TLSStream

from .auth import SMTPAuthenticator
from .protocol import SMTPClientProtocol, SMTPResponse, ClientState, SMTPException

logger = logging.getLogger(__name__)


@dataclass
class AsyncSMTPClient(AsyncResource):
    """
    An asynchronous SMTP client.

    This runs on asyncio or any other backend supported by AnyIO.

    It is recommended that this client is used as an async context manager instead of manually
    calling :meth:`~connect` and :meth:`aclose`, if possible.

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
    ssl_context: Optional[SSLContext] = None
    authenticator: Optional[SMTPAuthenticator] = None
    _protocol: SMTPClientProtocol = field(init=False, default_factory=SMTPClientProtocol)
    _stream: Union[TLSStream, SocketStream, None] = field(init=False, default=None)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

    async def connect(self) -> None:
        """Connect to the SMTP server."""
        if not self._stream:
            async with maybe_async_cm(fail_after(self.connect_timeout)):
                self._stream = await connect_tcp(self.host, self.port)

            try:
                await self._wait_response()
                await self._send_command(self._protocol.send_greeting, self.domain)

                # Do the TLS handshake if supported by the server
                if 'STARTTLS' in self._protocol.extensions:
                    await self._send_command(self._protocol.start_tls)
                    self._stream = await TLSStream.wrap(self._stream, hostname=self.host,
                                                        ssl_context=self.ssl_context,
                                                        standard_compatible=False)

                    # Send a new EHLO command to determine new capabilities
                    await self._send_command(self._protocol.send_greeting, self.domain)

                # Use the authenticator if one was provided
                if self.authenticator:
                    auth_gen = self.authenticator.authenticate()
                    try:
                        auth_data = await auth_gen.__anext__()
                        response = await self._send_command(
                            self._protocol.authenticate, self.authenticator.mechanism, auth_data)
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
                raise SMTPException('Not connected')

            if self._protocol.needs_incoming_data:
                try:
                    async with maybe_async_cm(fail_after(self.timeout)):
                        data = await self._stream.receive()
                except (BrokenResourceError, TimeoutError):
                    await aclose_forcefully(self._stream)
                    self._stream = None
                    raise

                logger.debug('Received: %s', data)
                response = self._protocol.feed_bytes(data)
                if response:
                    if response.is_error():
                        response.raise_as_exception()
                    else:
                        return response

                await self._flush_output()

    async def _flush_output(self) -> None:
        if not self._stream:
            raise SMTPException('Not connected')

        data = self._protocol.get_outgoing_data()
        if data:
            logger.debug('Sent: %s', data)
            try:
                async with maybe_async_cm(fail_after(self.timeout)):
                    await self._stream.send(data)
            except (BrokenResourceError, TimeoutError):
                await aclose_forcefully(self._stream)
                self._stream = None
                raise

    async def _send_command(self, command: Callable, *args) -> SMTPResponse:
        if not self._stream:
            raise SMTPException('Not connected')

        command(*args)
        await self._flush_output()
        return await self._wait_response()

    async def send_message(self, message: EmailMessage, *,
                           sender: Union[str, Address, None] = None,
                           recipients: Optional[Iterable[str]] = None) -> SMTPResponse:
        sender = sender or parseaddr(message.get('From'))[1]
        await self._send_command(self._protocol.mail, sender)

        if not recipients:
            tos: List[str] = message.get_all('to', [])
            ccs: List[str] = message.get_all('cc', [])
            resent_tos: List[str] = message.get_all('resent-to', [])
            resent_ccs: List[str] = message.get_all('resent-cc', [])
            recipients = [email for name, email in
                          getaddresses(tos + ccs + resent_tos + resent_ccs)]

        for recipient in recipients:
            await self._send_command(self._protocol.recipient, recipient)

        await self._send_command(self._protocol.start_data)
        return await self._send_command(self._protocol.data, message)


class SyncSMTPClient:
    """
    A synchronous (blocking) SMTP client.

    It is recommended that this client is used as a context manager instead of manually calling
    :meth:`~connect` and :meth:`close`, if possible.

    :param host: host name or IP address of the SMTP server
    :param port: port on the SMTP server to connect to
    :param connect_timeout: connection timeout (in seconds)
    :param timeout: timeout for sending requests and reading responses (in seconds)
    :param domain: domain name to send to the server as part of the greeting message
    :param ssl_context: SSL context to use for establishing TLS encrypted sessions
    :param authenticator: authenticator to use for authenticating with the SMTP server
    :param async_backend: name of the AnyIO-supported asynchronous backend
    :param async_backend_options: dictionary of keyword arguments passed to
        :func:`anyio.start_blocking_portal`
    """

    _portal: BlockingPortal

    def __init__(self, *args, async_backend: str = 'asyncio',
                 async_backend_options: Optional[Dict[str, Any]] = None, **kwargs):
        self._async_backend = async_backend
        self._async_backend_options = async_backend_options
        self._async_client = AsyncSMTPClient(*args, **kwargs)

    def __enter__(self):
        self._portal_cm = start_blocking_portal(self._async_backend, self._async_backend_options)
        self._portal = self._portal_cm.__enter__()
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        self._portal_cm.__exit__(exc_type, exc_val, exc_tb)

    def connect(self) -> None:
        """Connect to the SMTP server."""
        self._portal.call(self._async_client.connect)

    def close(self) -> None:
        """Close the connection, if connected."""
        self._portal.call(self._async_client.aclose)

    def send_message(self, message: EmailMessage, *,
                     sender: Union[str, Address, None] = None,
                     recipients: Optional[Iterable[str]] = None) -> SMTPResponse:
        func = partial(self._async_client.send_message, sender=sender, recipients=recipients)
        return self._portal.call(func, message)
