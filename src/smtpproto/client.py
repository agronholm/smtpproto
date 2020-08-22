import logging
import socket
from functools import partial

from dataclasses import dataclass, field
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from ssl import SSLContext
from typing import Optional, Iterable, Callable, Union, List, Dict, Any

from anyio import connect_tcp, fail_after, start_blocking_portal, aclose_forcefully
from anyio.abc import SocketStream, BlockingPortal, AsyncResource
from anyio.streams.tls import TLSStream

from .auth import SMTPAuthenticator
from .protocol import SMTPClientProtocol, SMTPResponse, ClientState, SMTPException

logger = logging.getLogger(__name__)


@dataclass
class AsyncSMTPClient(AsyncResource):
    """
    An example asynchronous SMTP client.

    :param host: host name or IP address of the SMTP server
    :param port: port on the SMTP server to connect to
    :param connect_timeout: connection timeout (in seconds)
    :param read_timeout: timeout for reading responses (in seconds)
    :param domain: domain name to send to the server as part of the greeting message
    :param ssl_context: SSL context to use for establishing TLS encrypted sessions
    :param authenticator: authenticator to use for authenticating with the SMTP server
    """

    host: str
    port: int = 587
    connect_timeout: float = 30
    read_timeout: float = 60
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
        if not self._stream:
            async with fail_after(self.connect_timeout):
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
                        auth_data = await auth_gen.asend(None)
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
                data = await self._stream.receive()
                logger.debug('Received: %s', data)
                response = self._protocol.feed_bytes(data)
                if response:
                    if response.is_error():
                        response.raise_as_exception()
                    else:
                        return response

            data = self._protocol.get_outgoing_data()
            if data:
                await self._stream.send(data)
                logger.debug('Sent: %s', data)

    async def _flush_output(self) -> None:
        data = self._protocol.get_outgoing_data()
        logger.debug('Sent: %s', data)
        async with fail_after(self.read_timeout):
            await self._stream.send(data)

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
    def __init__(self, *args, async_backend: str = 'asyncio',
                 async_backend_options: Optional[Dict[str, Any]] = None, **kwargs):
        self._async_backend = async_backend
        self._async_backend_options = async_backend_options
        self._async_client = AsyncSMTPClient(*args, **kwargs)
        self._portal: Optional[BlockingPortal] = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self) -> None:
        if not self._portal:
            self._portal = start_blocking_portal(self._async_backend, self._async_backend_options)
            try:
                self._portal.call(self._async_client.connect)
            except BaseException:
                self._portal.stop_from_external_thread()
                raise

    def close(self) -> None:
        if self._portal:
            try:
                self._portal.call(self._async_client.aclose)
            finally:
                self._portal.stop_from_external_thread()
                self._portal = None

    def send_message(self, message: EmailMessage, *,
                     sender: Union[str, Address, None] = None,
                     recipients: Optional[Iterable[str]] = None) -> SMTPResponse:
        func = partial(self._async_client.send_message, sender=sender, recipients=recipients)
        return self._portal.call(func, message)
