import re
from email.headerregistry import Address
from email.message import EmailMessage
from email.policy import SMTPUTF8, SMTP, Policy
from enum import Enum, auto
from typing import Iterable, Optional, List, Union, Tuple, FrozenSet, Sequence, NoReturn

import attr

response_re = re.compile('(\\d+)([- ])(.*)$')


class ClientState(Enum):
    """Enumerates all possible protocol states."""
    greeting_expected = auto()
    greeting_received = auto()
    authenticated = auto()
    ready = auto()
    mailtx = auto()
    recipient_sent = auto()
    send_data = auto()
    data_sent = auto()
    finished = auto()


class SMTPException(Exception):
    """Base class for SMTP exceptions."""


class SMTPMissingExtension(SMTPException):
    """Raised when a required SMTP extension is not present on the server."""


class SMTPProtocolViolation(SMTPException):
    """Raised when there has been a violation of the (E)SMTP protocol by either side."""


@attr.s(auto_attribs=True, slots=True, frozen=True)
class SMTPResponse:
    """Represents a response from the server."""
    code: int  #: response status code (between 100 and 599)
    message: str  #: response message

    def is_error(self) -> bool:
        """Return ``True`` if this is an error response, ``False`` if not."""
        return self.code >= 400

    def raise_as_exception(self) -> NoReturn:
        """Raise an :class:`SMTPException` from this response."""
        raise SMTPException(f'{self.code} {self.message}')


@attr.s(auto_attribs=True)
class SMTPClientProtocol:
    """The (E)SMTP protocol state machine."""

    _state: ClientState = attr.ib(init=False, default=ClientState.greeting_expected)
    _out_buffer: bytes = attr.ib(init=False, default=b'')
    _in_buffer: bytes = attr.ib(init=False, default=b'')
    _response_code: Optional[int] = attr.ib(init=False, default=None)
    _response_lines: List[str] = attr.ib(init=False, factory=list)
    _command_sent: Optional[str] = attr.ib(init=False, default=None)
    _args_sent: Optional[Tuple[str, ...]] = attr.ib(init=False, default=None)
    _extensions: FrozenSet[str] = attr.ib(init=False, factory=frozenset)
    _auth_mechanisms: FrozenSet[str] = attr.ib(init=False, factory=frozenset)
    _max_message_size: Optional[int] = attr.ib(init=False, default=None)

    def _require_state(self, *states: ClientState) -> None:
        if self._state not in states:
            allowed_states = ', '.join(state.name for state in states)
            raise SMTPProtocolViolation(f'Required state: one of: {allowed_states}; '
                                        f'current state: {self._state.name}')

    def _require_extension(self, extension: str) -> None:
        if extension not in self._extensions:
            raise SMTPMissingExtension(f'This operation requires the {extension} extension but '
                                       f'the server does not support it')

    def _send_command(self, command: str, *args: str) -> None:
        if self._command_sent is not None:
            raise SMTPProtocolViolation('Tried to send a command before the previous one received '
                                        'a response')

        line = command
        if args:
            line += ' ' + ' '.join(args)

        self._out_buffer += line.encode('ascii') + b'\r\n'
        self._command_sent = command
        self._args_sent = args

    def _parse_extensions(self, lines: Iterable[str]) -> None:
        auth_mechanisms: List[str] = []
        extensions = []
        for line in lines:
            extension, *params = line.split(' ')
            extension = extension.upper()
            if extension == 'AUTH':
                auth_mechanisms = params
            elif extension == 'SIZE':
                if params and params[0].isdigit():
                    self._max_message_size = int(params[0])

            extensions.append(extension)

        self._extensions = frozenset(extensions)
        self._auth_mechanisms = frozenset(auth_mechanisms)

    def _parse_response(self, code: int, lines: Sequence[str]) -> Optional[SMTPResponse]:
        command, args = self._command_sent, self._args_sent or ()
        self._command_sent = self._args_sent = None

        if code == 530 and 'AUTH' in self._extensions:
            # As per RFC 4954, authentication cannot be required for some commands
            if command not in ('AUTH', 'EHLO', 'HELO', 'NOOP', 'RSET', 'QUIT'):
                return SMTPResponse(code, '\n'.join(lines))

        if command is None:
            if self._state is ClientState.data_sent:
                if code == 250:
                    self._state = ClientState.ready
                    return SMTPResponse(code, '\n'.join(lines))
            elif self._state is ClientState.greeting_expected:
                if code == 220:
                    self._state = ClientState.greeting_received
                    return SMTPResponse(code, '\n'.join(lines))
                elif code == 554:
                    self._state = ClientState.finished
                    return SMTPResponse(code, '\n'.join(lines))
        elif command == 'EHLO':
            if code == 250:
                self._state = ClientState.ready
                self._parse_extensions(lines[1:])
                return SMTPResponse(code, '\n'.join(lines))
            elif code == 500:  # old SMTP server; try the RFC 821 HELO instead
                self._send_command('HELO', *args)
                return None
            elif code in (504, 550):
                return SMTPResponse(code, '\n'.join(lines))
        elif command == 'HELO':
            if code == 250:
                self._state = ClientState.ready
                return SMTPResponse(code, '\n'.join(lines))
            elif code in (502, 504, 550):
                return SMTPResponse(code, '\n'.join(lines))
        elif command == 'NOOP':
            if code == 250:
                return SMTPResponse(code, '\n'.join(lines))
        elif command == 'QUIT':
            if code == 221:
                self._state = ClientState.finished
                return SMTPResponse(code, '\n'.join(lines))
        elif command == 'MAIL':
            if code == 250:
                self._state = ClientState.mailtx
                return SMTPResponse(code, '\n'.join(lines))
            elif code in (451, 452, 455, 503, 550, 553, 552, 555):
                return SMTPResponse(code, '\n'.join(lines))
        elif command == 'RCPT':
            if code in (250, 251):
                self._state = ClientState.recipient_sent
                return SMTPResponse(code, '\n'.join(lines))
            elif code in (450, 451, 452, 455, 503, 550, 551, 552, 553, 555):
                return SMTPResponse(code, '\n'.join(lines))
        elif command == 'DATA':
            if code == 354:
                self._state = ClientState.send_data
                return SMTPResponse(code, '\n'.join(lines))
            elif code in (450, 451, 452, 503, 550, 552, 554):
                return SMTPResponse(code, '\n'.join(lines))
        elif command == 'RSET':
            if code == 250:
                self._state = ClientState.ready
                return SMTPResponse(code, '\n'.join(lines))
        elif command == 'STARTTLS':
            if code == 220:
                self._state = ClientState.greeting_received
                return SMTPResponse(code, '\n'.join(lines))
        elif command == 'AUTH':
            if code == 235:
                self._state = ClientState.authenticated
                return SMTPResponse(code, '\n'.join(lines))
            elif code in (432, 454, 500, 534, 535, 538):
                return SMTPResponse(code, '\n'.join(lines))

        self._state = ClientState.finished
        raise SMTPProtocolViolation(f'Unexpected response: {code} ' + '\n'.join(lines))

    @property
    def state(self) -> ClientState:
        """The current state of the protocol."""
        return self._state

    @property
    def needs_incoming_data(self) -> bool:
        """``True`` if the state machine requires more data, ``False`` if not."""
        return (self._state in (ClientState.greeting_expected, ClientState.data_sent)
                or self._command_sent is not None)

    def get_outgoing_data(self) -> bytes:
        """Retrieve any bytes to be sent to the server."""
        buffer = self._out_buffer
        self._out_buffer = b''
        return buffer

    @property
    def max_message_size(self) -> Optional[int]:
        """The maximum size of the email message (in bytes) accepted by the server."""
        return self._max_message_size

    @property
    def auth_mechanisms(self) -> FrozenSet[str]:
        """The set of authentication mechanisms supported on the server."""
        return self._auth_mechanisms

    @property
    def extensions(self) -> FrozenSet[str]:
        """Return ``True`` if the server has declared that it has the given extension."""
        return self._extensions

    def authenticate(self, mechanism: str, secret: str) -> None:
        """
        Authenticate to the server using the given mechanism and an accompanying secret.

        :param mechanism: the authentication mechanism (e.g. ``PLAIN`` or ``GSSAPI``)
        :param secret: the credentials to authenticate with (specific to each authentication
            mechanism)

        """
        self._require_state(ClientState.ready)
        self._require_extension('AUTH')
        self._send_command('AUTH', mechanism, secret)

    def send_greeting(self, domain: str) -> None:
        """
        Send the initial greeting (EHLO or HELO).

        :param domain: the required domain name that represents the client side

        """
        self._require_state(ClientState.greeting_received)
        self._send_command('EHLO', domain)

    def noop(self) -> None:
        """Send the NOOP command (No Operation)."""
        self._send_command('NOOP')

    def quit(self) -> None:
        """Send the QUIT command (required to cleanly shut down the session)."""
        self._send_command('QUIT')

    def mail(self, sender: Union[str, Address]) -> None:
        """
        Send the MAIL FROM command (starts a mail transaction).

        :param sender: the sender's email address

        """
        self._require_state(ClientState.ready, ClientState.authenticated)

        args = []
        if '8BITMIME' in self._extensions:
            args.append('BODY=8BITMIME')

        address = sender.addr_spec if isinstance(sender, Address) else sender
        self._send_command('MAIL', 'FROM:<' + address + '>', *args)

    def recipient(self, recipient: Union[str, Address]) -> None:
        """
        Send the RCPT TO command (declare an intended recipient).

        Requires an active mail transaction.

        :param recipient: the recipient's email address

        """
        self._require_state(ClientState.mailtx, ClientState.recipient_sent)
        address = recipient.addr_spec if isinstance(recipient, Address) else recipient
        self._send_command('RCPT', f'TO:<{address}>')

    def start_data(self) -> None:
        """
        Send the DATA command (prepare for sending the email payload).

        Requires an active mail transaction, and that at least one recipient has been declared.

        """
        self._require_state(ClientState.recipient_sent)
        self._send_command('DATA')

    def data(self, message: EmailMessage) -> None:
        """
        Send the actual email payload.

        Requires that the DATA command has been sent first.

        :param message: the email message

        """
        self._require_state(ClientState.send_data)
        policy: Policy = SMTPUTF8 if 'SMTPUTF8' in self._extensions else SMTP
        policy = policy.clone(cte_type='7bit') if '8BITMIME' not in self._extensions else policy
        self._out_buffer += message.as_bytes(policy=policy).replace(b'\r\n.', b'\r\n..')
        self._out_buffer += b'.\r\n'
        self._state = ClientState.data_sent

    def reset(self) -> None:
        """Send the RSET command (cancel the active mail transaction)."""
        self._require_state(ClientState.mailtx, ClientState.recipient_sent, ClientState.send_data)
        self._send_command('RSET')

    def start_tls(self) -> None:
        """Send the STARTTLS command (signal the server to initiate a TLS handshake)."""
        self._require_state(ClientState.ready)
        self._require_extension('STARTTLS')
        self._send_command('STARTTLS')

    def feed_bytes(self, data: bytes) -> Optional[SMTPResponse]:
        """
        Feed received bytes from the transport into the state machine.

        if this method raises :exc:`SMTPProtocolViolation`, the state machine is transitioned to
        the ``finished`` state, and the connection should be closed.

        :param data: received bytes
        :return: a response object if a complete response was received, ``None`` otherwise
        :raises SMTPProtocolViolation: if the server sent an invalid response

        """
        self._in_buffer += data
        start = 0
        while True:
            end = self._in_buffer.find(b'\r\n', start)
            if end < 0:
                # If there's an unfinished line, save it in the buffer
                self._in_buffer = self._in_buffer[start:]
                return None

            # Check that the format of each line matches the expected one
            line = self._in_buffer[start:end].decode('ascii')
            start = end + 2
            match = response_re.match(line)
            if not match:
                self._state = ClientState.finished
                raise SMTPProtocolViolation(f'Invalid input: {line}')

            code = int(match.group(1))
            continues = match.group(2) == '-'
            message = match.group(3)
            if self._response_code is None:
                self._response_code = code
            elif self._response_code != code:
                self._state = ClientState.finished
                raise SMTPProtocolViolation(
                    f'Expected code {self._response_code}, got {code} instead')

            self._response_lines.append(message)
            if not continues:
                response_code = self._response_code
                response_lines = self._response_lines
                self._response_code = None
                self._response_lines = []
                self._in_buffer = self._in_buffer[start:]
                return self._parse_response(response_code, response_lines)
