from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from email.headerregistry import Address
from email.message import EmailMessage
from email.policy import SMTP, SMTPUTF8, Policy
from enum import Enum, auto
from re import Pattern
from typing import NoReturn

response_re: Pattern[str] = re.compile("(\\d+)([- ])(.*)$")


class ClientState(Enum):
    """Enumerates all possible protocol states."""

    greeting_expected = auto()  #: expecting a greeting from the server
    greeting_received = (
        auto()
    )  #: received a greeting from the server, ready to authenticate
    authenticating = auto()  #: authentication in progress
    authenticated = auto()  #: authentication done
    ready = auto()  #: ready to send commands
    mailtx = auto()  #: in a mail transaction
    recipient_sent = auto()  #: sent at least one recipient
    send_data = auto()  #: ready to send the message data
    data_sent = auto()  #: message data sent
    finished = auto()  #: session finished


class SMTPException(Exception):
    """Base class for SMTP exceptions."""


class SMTPMissingExtension(SMTPException):
    """Raised when a required SMTP extension is not present on the server."""


class SMTPUnsupportedAuthMechanism(SMTPException):
    """
    Raised when trying to authenticate using a mechanism not supported by the server.
    """


class SMTPProtocolViolation(SMTPException):
    """Raised when there has been a violation of the (E)SMTP protocol by either side."""


@dataclass(frozen=True)
class SMTPResponse:
    """Represents a response from the server."""

    code: int  #: response status code (between 100 and 599)
    message: str  #: response message

    def is_error(self) -> bool:
        """Return ``True`` if this is an error response, ``False`` if not."""
        return self.code >= 400

    def raise_as_exception(self) -> NoReturn:
        """Raise an :class:`SMTPException` from this response."""
        raise SMTPException(f"{self.code} {self.message}")


@dataclass
class SMTPClientProtocol:
    """The (E)SMTP protocol state machine."""

    _state: ClientState = field(init=False, default=ClientState.greeting_expected)
    _smtputf8_message: bool = field(init=False, default=True)
    _out_buffer: bytes = field(init=False, default=b"")
    _in_buffer: bytes = field(init=False, default=b"")
    _response_code: int | None = field(init=False, default=None)
    _response_lines: list[str] = field(init=False, default_factory=list)
    _command_sent: str | None = field(init=False, default=None)
    _args_sent: tuple[bytes, ...] | None = field(init=False, default=None)
    _extensions: frozenset[str] = field(init=False, default_factory=frozenset)
    _auth_mechanisms: frozenset[str] = field(init=False, default_factory=frozenset)
    _max_message_size: int | None = field(init=False, default=None)

    def _require_state(self, *states: ClientState) -> None:
        if self._state not in states:
            allowed_states = ", ".join(state.name for state in states)
            raise SMTPProtocolViolation(
                f"Required state: one of: {allowed_states}; "
                f"current state: {self._state.name}"
            )

    def _require_extension(self, extension: str) -> None:
        if extension not in self._extensions:
            raise SMTPMissingExtension(
                f"This operation requires the {extension} extension but "
                f"the server does not support it"
            )

    def _require_auth_mechanism(self, mechanism) -> None:
        if mechanism not in self._auth_mechanisms:
            raise SMTPUnsupportedAuthMechanism(
                f"{mechanism} is not a supported authentication mechanism on this "
                f"server"
            )

    def _encode_address(self, address: str | Address) -> bytes:
        if isinstance(address, Address):
            address_str = f"{address.username}@{address.domain}"
        else:
            address_str = address

        if self._smtputf8_message:
            return address_str.encode("utf-8")

        # If SMPTUTF8 is not supported, the address must be ASCII compatible
        try:
            return address_str.encode("ascii")
        except UnicodeEncodeError:
            if "SMTPUTF8" in self._extensions:
                raise SMTPProtocolViolation(
                    f"The address {address_str!r} requires UTF-8 encoding but "
                    f"`smtputf8` was not specified in the mail command"
                )
            else:
                raise SMTPProtocolViolation(
                    f"The address {address_str!r} requires UTF-8 encoding but the "
                    f"server does not support the SMTPUTF8 extension"
                )

    def _send_command(self, command: str, *args: str | bytes) -> None:
        if self._command_sent is not None:
            raise SMTPProtocolViolation(
                "Tried to send a command before the previous one received " "a response"
            )

        line = command.encode("ascii")
        args_encoded = tuple(
            arg.encode("ascii") if isinstance(arg, str) else arg for arg in args
        )
        if args_encoded:
            line += b" " + b" ".join(args_encoded)

        self._out_buffer += line + b"\r\n"
        self._command_sent = command
        self._args_sent = args_encoded

    def _parse_extensions(self, lines: Iterable[str]) -> None:
        auth_mechanisms: list[str] = []
        extensions = []
        for line in lines:
            extension, *params = line.split(" ")
            extension = extension.upper()
            if extension == "AUTH":
                auth_mechanisms = params
            elif extension == "SIZE":
                if params and params[0].isdigit():
                    self._max_message_size = int(params[0])

            extensions.append(extension)

        self._extensions = frozenset(extensions)
        self._auth_mechanisms = frozenset(auth_mechanisms)

    def _parse_response(self, code: int, lines: Sequence[str]) -> SMTPResponse | None:
        command, args = self._command_sent, self._args_sent or ()
        self._command_sent = self._args_sent = None

        if self._state is ClientState.authenticating or command == "AUTH":
            if code == 334:
                self._state = ClientState.authenticating
                return SMTPResponse(code, "\n".join(lines))
            elif code == 235:
                self._state = ClientState.authenticated
                return SMTPResponse(code, "\n".join(lines))
            elif code in (432, 454, 500, 534, 535, 538):
                self._state = ClientState.ready
                return SMTPResponse(code, "\n".join(lines))

        if code == 530 and "AUTH" in self._extensions:
            # As per RFC 4954, authentication cannot be required for some commands
            if command not in ("AUTH", "EHLO", "HELO", "NOOP", "RSET", "QUIT"):
                return SMTPResponse(code, "\n".join(lines))

        if command is None:
            if self._state is ClientState.data_sent:
                if code == 250:
                    self._state = ClientState.ready
                    return SMTPResponse(code, "\n".join(lines))
            elif self._state is ClientState.greeting_expected:
                if code == 220:
                    self._state = ClientState.greeting_received
                    return SMTPResponse(code, "\n".join(lines))
                elif code == 554:
                    self._state = ClientState.finished
                    return SMTPResponse(code, "\n".join(lines))
        elif command == "EHLO":
            if code == 250:
                self._state = ClientState.ready
                self._parse_extensions(lines[1:])
                return SMTPResponse(code, "\n".join(lines))
            elif code == 500:  # old SMTP server; try the RFC 821 HELO instead
                self._send_command("HELO", *args)
                return None
            elif code in (504, 550):
                return SMTPResponse(code, "\n".join(lines))
        elif command == "HELO":
            if code == 250:
                self._state = ClientState.ready
                return SMTPResponse(code, "\n".join(lines))
            elif code in (502, 504, 550):
                return SMTPResponse(code, "\n".join(lines))
        elif command == "NOOP":
            if code == 250:
                return SMTPResponse(code, "\n".join(lines))
        elif command == "QUIT":
            if code == 221:
                self._state = ClientState.finished
                return SMTPResponse(code, "\n".join(lines))
        elif command == "MAIL":
            if code == 250:
                self._state = ClientState.mailtx
                return SMTPResponse(code, "\n".join(lines))
            elif code in (451, 452, 455, 503, 550, 553, 552, 555):
                return SMTPResponse(code, "\n".join(lines))
        elif command == "RCPT":
            if code in (250, 251):
                self._state = ClientState.recipient_sent
                return SMTPResponse(code, "\n".join(lines))
            elif code in (450, 451, 452, 455, 503, 550, 551, 552, 553, 555):
                return SMTPResponse(code, "\n".join(lines))
        elif command == "DATA":
            if code == 354:
                self._state = ClientState.send_data
                return SMTPResponse(code, "\n".join(lines))
            elif code in (450, 451, 452, 503, 550, 552, 554):
                return SMTPResponse(code, "\n".join(lines))
        elif command == "RSET":
            if code == 250:
                self._state = ClientState.ready
                return SMTPResponse(code, "\n".join(lines))
        elif command == "STARTTLS":
            if code == 220:
                self._state = ClientState.greeting_received
                return SMTPResponse(code, "\n".join(lines))

        self._state = ClientState.finished
        raise SMTPProtocolViolation(f"Unexpected response: {code} " + "\n".join(lines))

    @property
    def state(self) -> ClientState:
        """The current state of the protocol."""
        return self._state

    @property
    def needs_incoming_data(self) -> bool:
        """``True`` if the state machine requires more data, ``False`` if not."""
        return (
            self._state in (ClientState.greeting_expected, ClientState.data_sent)
            or self._command_sent is not None
        )

    def get_outgoing_data(self) -> bytes:
        """Retrieve any bytes to be sent to the server."""
        buffer = self._out_buffer
        self._out_buffer = b""
        return buffer

    @property
    def max_message_size(self) -> int | None:
        """The maximum size of the email message (in bytes) accepted by the server."""
        return self._max_message_size

    @property
    def auth_mechanisms(self) -> frozenset[str]:
        """The set of authentication mechanisms supported on the server."""
        return self._auth_mechanisms

    @property
    def extensions(self) -> frozenset[str]:
        """The set of extensions advertised by the server."""
        return self._extensions

    def authenticate(self, mechanism: str, secret: str | None = None) -> None:
        """
        Authenticate to the server using the given mechanism and an accompanying secret.

        :param mechanism: the authentication mechanism (e.g. ``PLAIN`` or ``GSSAPI``)
        :param secret: an optional string (usually containing the credentials) that is
            added as an argument to the ``AUTH XXX`` command

        """
        self._require_state(ClientState.ready)
        self._require_extension("AUTH")
        self._require_auth_mechanism(mechanism)
        if secret:
            self._send_command("AUTH", mechanism, secret)
        else:
            self._send_command("AUTH", mechanism)

    def send_authentication_data(self, data: str) -> None:
        """
        Send authentication data to the server.

        This method can be called when the server responds with a 334 to an AUTH
        command.

        :param data: authentication data (ASCII compatible; usually base64 encoded)

        """
        self._require_state(ClientState.authenticating)
        self._send_command(data)

    def send_greeting(self, domain: str) -> None:
        """
        Send the initial greeting (EHLO or HELO).

        :param domain: the required domain name that represents the client side

        """
        self._require_state(ClientState.greeting_received)
        self._send_command("EHLO", domain)

    def noop(self) -> None:
        """Send the NOOP command (No Operation)."""
        self._send_command("NOOP")

    def quit(self) -> None:
        """Send the QUIT command (required to cleanly shut down the session)."""
        self._send_command("QUIT")

    def mail(self, sender: str | Address, *, smtputf8: bool = True) -> None:
        """
        Send the MAIL FROM command (starts a mail transaction).

        :param sender: the sender's email address
        :param smtputf8: send the SMTPUTF8 option, if available on the server

        """
        self._require_state(ClientState.ready, ClientState.authenticated)

        args = []
        if "8BITMIME" in self._extensions:
            args.append("BODY=8BITMIME")

        if smtputf8 and "SMTPUTF8" in self._extensions:
            self._smtputf8_message = True
            args.append("SMTPUTF8")
        else:
            self._smtputf8_message = False

        self._send_command(
            "MAIL", b"FROM:<" + self._encode_address(sender) + b">", *args
        )

    def recipient(self, recipient: str | Address) -> None:
        """
        Send the RCPT TO command (declare an intended recipient).

        Requires an active mail transaction.

        :param recipient: the recipient's email address

        """
        self._require_state(ClientState.mailtx, ClientState.recipient_sent)
        self._send_command("RCPT", b"TO:<" + self._encode_address(recipient) + b">")

    def start_data(self) -> None:
        """
        Send the DATA command (prepare for sending the email payload).

        Requires an active mail transaction, and that at least one recipient has been
        declared.

        """
        self._require_state(ClientState.recipient_sent)
        self._send_command("DATA")

    def data(self, message: EmailMessage) -> None:
        """
        Send the actual email payload.

        Requires that the DATA command has been sent first.

        :param message: the email message

        """
        self._require_state(ClientState.send_data)
        policy: Policy = SMTPUTF8 if self._smtputf8_message else SMTP
        policy = (
            policy.clone(cte_type="7bit")
            if "8BITMIME" not in self._extensions
            else policy
        )
        self._out_buffer += message.as_bytes(policy=policy).replace(b"\r\n.", b"\r\n..")
        self._out_buffer += b".\r\n"
        self._state = ClientState.data_sent

    def reset(self) -> None:
        """Send the RSET command (cancel the active mail transaction)."""
        self._require_state(
            ClientState.mailtx, ClientState.recipient_sent, ClientState.send_data
        )
        self._send_command("RSET")

    def start_tls(self) -> None:
        """Send the STARTTLS command (signal the server to initiate a TLS handshake)."""
        self._require_state(ClientState.ready)
        self._require_extension("STARTTLS")
        self._send_command("STARTTLS")

    def feed_bytes(self, data: bytes) -> SMTPResponse | None:
        """
        Feed received bytes from the transport into the state machine.

        if this method raises :exc:`SMTPProtocolViolation`, the state machine is
        transitioned to the ``finished`` state, and the connection should be closed.

        :param data: received bytes
        :return: a response object if a complete response was received, ``None``
            otherwise
        :raises SMTPProtocolViolation: if the server sent an invalid response

        """
        self._in_buffer += data
        start = 0
        while True:
            end = self._in_buffer.find(b"\r\n", start)
            if end < 0:
                # If there's an unfinished line, save it in the buffer
                self._in_buffer = self._in_buffer[start:]
                return None

            # Check that the format of each line matches the expected one
            line = self._in_buffer[start:end].decode("ascii")
            start = end + 2
            match = response_re.match(line)
            if not match:
                self._state = ClientState.finished
                raise SMTPProtocolViolation(f"Invalid input: {line}")

            code = int(match.group(1))
            continues = match.group(2) == "-"
            message = match.group(3)
            if self._response_code is None:
                self._response_code = code
            elif self._response_code != code:
                self._state = ClientState.finished
                raise SMTPProtocolViolation(
                    f"Expected code {self._response_code}, got {code} instead"
                )

            self._response_lines.append(message)
            if not continues:
                response_code = self._response_code
                response_lines = self._response_lines
                self._response_code = None
                self._response_lines = []
                self._in_buffer = self._in_buffer[start:]
                return self._parse_response(response_code, response_lines)
