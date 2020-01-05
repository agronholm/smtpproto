import logging
import socket
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from ssl import SSLContext
from typing import Optional, Iterable, Callable, Union, List

import attr
from anyio import connect_tcp
from anyio.abc import SocketStream

from .async_auth import SMTPCredentialsProvider
from .protocol import SMTPClientProtocol, SMTPResponse, ClientState, SMTPError

logger = logging.getLogger(__name__)


@attr.s(auto_attribs=True, kw_only=True)
class AsyncSMTPClient:
    host: str
    port: int = 587
    domain: str = attr.ib(factory=socket.gethostname)
    ssl_context: Optional[SSLContext] = None
    credentials_provider: Optional[SMTPCredentialsProvider] = None
    _protocol: SMTPClientProtocol = attr.ib(init=False, factory=SMTPClientProtocol)
    _stream: Optional[SocketStream] = attr.ib(init=False, default=None)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

    async def connect(self) -> None:
        if not self._stream:
            self._stream = await connect_tcp(self.host, self.port, ssl_context=self.ssl_context,
                                             tls_standard_compatible=False)
            try:
                await self._wait_response()
                await self._send_command(self._protocol.send_greeting, self.domain)

                # Do the TLS handshake if supported by the server
                if 'STARTTLS' in self._protocol.extensions:
                    await self._send_command(self._protocol.start_tls)
                    await self._stream.start_tls()

                    # Send a new EHLO command to determine new capabilities
                    await self._send_command(self._protocol.send_greeting, self.domain)

                # Authenticate if credentials provided
                if self.credentials_provider:
                    credentials = await self.credentials_provider.get_credentials()
                    await self._send_command(self._protocol.authenticate,
                                             self.credentials_provider.mechanism, credentials)
            except BaseException:
                await self.aclose()
                raise

    async def aclose(self) -> None:
        if self._stream:
            try:
                if self._protocol.state is not ClientState.finished:
                    await self._send_command(self._protocol.quit)
            finally:
                await self._stream.close()
                self._stream = None

    async def _wait_response(self) -> SMTPResponse:
        while True:
            if not self._stream:
                raise SMTPError('Not connected')

            if self._protocol.needs_incoming_data:
                data = await self._stream.receive_some(65536)
                logger.debug('Received: %s', data)
                response = self._protocol.feed_bytes(data)
                if response:
                    return response

            data = self._protocol.get_outgoing_data()
            if data:
                await self._stream.send_all(data)
                logger.debug('Sent: %s', data)

    async def _send_command(self, command: Callable, *args) -> SMTPResponse:
        if not self._stream:
            raise SMTPError('Not connected')

        command(*args)
        data = self._protocol.get_outgoing_data()
        logger.debug('Sent: %s', data)
        await self._stream.send_all(data)
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
