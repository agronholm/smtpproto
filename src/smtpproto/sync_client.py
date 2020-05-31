import logging
import socket
from dataclasses import dataclass, field
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from ssl import SSLContext, SSLSocket, create_default_context
from typing import Optional, Iterable, Callable, Union, List

from .auth import SMTPCredentialsProvider
from .protocol import SMTPClientProtocol, SMTPResponse, ClientState, SMTPException

logger = logging.getLogger(__name__)


@dataclass
class SMTPClient:
    """
    An example blocking SMTP client.

    :param host: host name or IP address of the SMTP server
    :param port: port on the SMTP server to connect to
    :param connect_timeout: connection timeout (in seconds)
    :param read_timeout: timeout for reading responses (in seconds)
    :param domain: domain name to send to the server as part of the greeting message
    :param ssl_context: SSL context to use for establishing TLS encrypted sessions
    :param credentials_provider: credentials to use for authenticating with the SMTP server
    """

    host: str
    port: int = 587
    connect_timeout: float = 30
    read_timeout: float = 60
    domain: str = field(default_factory=socket.gethostname)
    ssl_context: Optional[SSLContext] = field(default_factory=create_default_context)
    credentials_provider: Optional[SMTPCredentialsProvider] = None
    _protocol: SMTPClientProtocol = field(init=False, default_factory=SMTPClientProtocol)
    _socket: Union[socket.socket, SSLSocket, None] = field(init=False, default=None)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self) -> None:
        if not self._socket:
            self._socket = socket.create_connection((self.host, self.port), self.connect_timeout)
            self._socket.settimeout(self.read_timeout)
            try:
                self._wait_response()
                self._send_command(self._protocol.send_greeting, self.domain)

                # Do the TLS handshake if supported by the server
                if 'STARTTLS' in self._protocol.extensions:
                    self._send_command(self._protocol.start_tls)
                    self._socket = self.ssl_context.wrap_socket(self._socket,
                                                                server_hostname=self.host)

                    # Send a new EHLO command to determine new capabilities
                    self._send_command(self._protocol.send_greeting, self.domain)

                # Authenticate if credentials provided
                if self.credentials_provider:
                    credentials = self.credentials_provider.get_credentials_sync()
                    self._send_command(self._protocol.authenticate,
                                             self.credentials_provider.mechanism, credentials)
            except BaseException:
                self.close()
                raise

    def close(self) -> None:
        if self._socket:
            try:
                if self._protocol.state is not ClientState.finished:
                    self._send_command(self._protocol.quit)
            finally:
                self._socket.close()
                self._socket = None

    def _wait_response(self) -> SMTPResponse:
        while True:
            if not self._socket:
                raise SMTPException('Not connected')

            if self._protocol.needs_incoming_data:
                data = self._socket.recv(65536)
                logger.debug('Received: %s', data)
                response = self._protocol.feed_bytes(data)
                if response:
                    if response.is_error():
                        response.raise_as_exception()
                    else:
                        return response

            data = self._protocol.get_outgoing_data()
            if data:
                self._socket.sendall(data)
                logger.debug('Sent: %s', data)

    def _send_command(self, command: Callable, *args) -> SMTPResponse:
        if not self._socket:
            raise SMTPException('Not connected')

        command(*args)
        data = self._protocol.get_outgoing_data()
        logger.debug('Sent: %s', data)
        self._socket.sendall(data)
        return self._wait_response()

    def send_message(self, message: EmailMessage, *,
                     sender: Union[str, Address, None] = None,
                     recipients: Optional[Iterable[str]] = None) -> SMTPResponse:
        sender = sender or parseaddr(message.get('From'))[1]
        self._send_command(self._protocol.mail, sender)

        if not recipients:
            tos: List[str] = message.get_all('to', [])
            ccs: List[str] = message.get_all('cc', [])
            resent_tos: List[str] = message.get_all('resent-to', [])
            resent_ccs: List[str] = message.get_all('resent-cc', [])
            recipients = [email for name, email in
                          getaddresses(tos + ccs + resent_tos + resent_ccs)]

        for recipient in recipients:
            self._send_command(self._protocol.recipient, recipient)

        self._send_command(self._protocol.start_data)
        return self._send_command(self._protocol.data, message)
