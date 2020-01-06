from email.headerregistry import Address
from email.message import EmailMessage
from typing import Optional, Callable

import pytest

from smtpproto.protocol import (
    SMTPClientProtocol, ClientState, SMTPProtocolViolation,
    SMTPErrorResponse, SMTPMissingExtension)


def call_protocol_method(protocol: SMTPClientProtocol, func: Callable,
                         expected_outgoing_data: bytes):
    assert not protocol.needs_incoming_data
    func()
    assert protocol.get_outgoing_data() == expected_outgoing_data


def feed_bytes(protocol: SMTPClientProtocol, data: bytes, expected_code: Optional[int] = None,
               expected_message: Optional[str] = None,
               expected_state: Optional[ClientState] = None):
    assert protocol.needs_incoming_data
    response = protocol.feed_bytes(data)
    if expected_code:
        assert response.code == expected_code
        assert not protocol.needs_incoming_data
    else:
        assert response is None
        assert protocol.needs_incoming_data

    if expected_message:
        assert response.message == expected_message
    if expected_state:
        assert protocol.state is expected_state


def exchange_greetings(protocol, esmtp=True):
    # Server sends a greeting message
    feed_bytes(protocol, b'220 foo.bar SMTP service ready\r\n', 220, 'foo.bar SMTP service ready',
               ClientState.greeting_received)

    # Do the ESMTP handshake
    call_protocol_method(protocol, lambda: protocol.send_greeting('foo.bar'), b'EHLO foo.bar\r\n')
    if esmtp:
        feed_bytes(protocol, b'250-foo.bar ready\r\n')
        feed_bytes(protocol, b'250-8BITMIME\r\n')
        feed_bytes(protocol, b'250-SMTPUTF8\r\n')
        feed_bytes(protocol, b'250-STARTTLS\r\n')
        feed_bytes(protocol, b'250-SIZE 10000000\r\n')
        feed_bytes(protocol, b'250 AUTH PLAIN\r\n', 250,
                   'foo.bar ready\n8BITMIME\nSMTPUTF8\nSTARTTLS\nSIZE 10000000\nAUTH PLAIN',
                   ClientState.ready)
        assert protocol.extensions == {'8BITMIME', 'SMTPUTF8', 'STARTTLS', 'SIZE', 'AUTH'}
        assert protocol.auth_mechanisms == {'PLAIN'}
        assert protocol.max_message_size == 10000000
    else:
        # Fall back to HELO
        feed_bytes(protocol, b'500 Unknown command\r\n')
        assert protocol.get_outgoing_data() == b'HELO foo.bar\r\n'
        feed_bytes(protocol, b'250 foo.bar ready\r\n', 250, 'foo.bar ready', ClientState.ready)
        assert protocol.extensions == frozenset()
        assert protocol.auth_mechanisms == frozenset()
        assert protocol.max_message_size is None


def start_mail_tx(protocol):
    # Start a mail transaction
    extra_args = b' BODY=8BITMIME' if '8BITMIME' in protocol.extensions else b''
    call_protocol_method(protocol, lambda: protocol.mail('foo@bar.com'),
                         b'MAIL FROM:<foo@bar.com>' + extra_args + b'\r\n')
    feed_bytes(protocol, b'250 OK\r\n', 250, 'OK', ClientState.mailtx)

    # Declare the first recipient
    call_protocol_method(protocol, lambda: protocol.recipient('recipient1@domain.com'),
                         b'RCPT TO:<recipient1@domain.com>\r\n')
    feed_bytes(protocol, b'250 OK\r\n', 250, 'OK', ClientState.recipient_sent)

    # Declare the second recipient, this time using an Address
    address = Address('Firstname Lastname', 'recipient2', 'domain.com')
    call_protocol_method(protocol, lambda: protocol.recipient(address),
                         b'RCPT TO:<recipient2@domain.com>\r\n')
    feed_bytes(protocol, b'250 OK\r\n', 250, 'OK', ClientState.recipient_sent)

    # Declare the start of the message data
    call_protocol_method(protocol, protocol.start_data, b'DATA\r\n')
    feed_bytes(protocol, b'354 Start mail input; end with <CRLF>.<CRLF>\r\n', 354,
               'Start mail input; end with <CRLF>.<CRLF>', ClientState.send_data)


@pytest.fixture
def protocol():
    proto = SMTPClientProtocol()
    assert proto.state is ClientState.greeting_expected
    assert proto.needs_incoming_data
    return proto


@pytest.mark.parametrize('esmtp, expected_cte, expected_subject, expected_body', [
    pytest.param(True, '8bit', 'This is a subjëct', 'This is ä test message.', id='8bit'),
    pytest.param(False, 'base64', 'This is a =?utf-8?q?subj=C3=ABct?=',
                 'VGhpcyBpcyDDpCB0ZXN0IG1lc3NhZ2UuCg==', id='7bit')
])
def test_send_mail_utf8(protocol, esmtp, expected_cte, expected_subject, expected_body):
    exchange_greetings(protocol, esmtp=esmtp)
    start_mail_tx(protocol)

    message = EmailMessage()
    message['Subject'] = 'This is a subjëct'
    message.set_content('This is ä test message.')
    call_protocol_method(protocol, lambda: protocol.data(message),
                         f'Subject: {expected_subject}\r\n'
                         f'Content-Type: text/plain; charset="utf-8"\r\n'
                         f'Content-Transfer-Encoding: {expected_cte}\r\n'
                         f'MIME-Version: 1.0\r\n\r\n'
                         f'{expected_body}\r\n.\r\n'.encode('utf-8'))
    feed_bytes(protocol, b'250 OK\r\n', 250, 'OK', ClientState.ready)


def test_send_mail_escape_dots(protocol):
    exchange_greetings(protocol)
    start_mail_tx(protocol)

    message = EmailMessage()
    message.set_content('The following lines might trip the protocol:\n.test\n.')
    call_protocol_method(protocol, lambda: protocol.data(message),
                         'Content-Type: text/plain; charset="utf-8"\r\n'
                         'Content-Transfer-Encoding: 7bit\r\n'
                         'MIME-Version: 1.0\r\n\r\n'
                         'The following lines might trip the protocol:\r\n'
                         '..test\r\n'
                         '..\r\n'
                         '.\r\n'.encode('utf-8'))
    feed_bytes(protocol, b'250 OK\r\n', 250, 'OK', ClientState.ready)


def test_reset_mail_tx(protocol):
    exchange_greetings(protocol)
    start_mail_tx(protocol)
    call_protocol_method(protocol, protocol.reset, b'RSET\r\n')
    feed_bytes(protocol, b'250 OK\r\n', 250, 'OK', ClientState.ready)


def test_bad_greeting(protocol):
    pytest.raises(SMTPErrorResponse, feed_bytes, protocol, b'554 Go away\r\n').match('554 Go away')


def test_premature_greeting(protocol):
    pytest.raises(SMTPProtocolViolation, protocol.send_greeting, 'foo.bar').\
        match('Required state: one of: greeting_received; current state: greeting_expected')


def test_double_command(protocol):
    protocol.noop()
    pytest.raises(SMTPProtocolViolation, protocol.noop).\
        match('Tried to send a command before the previous one received a response')


def test_authentication_required(protocol):
    exchange_greetings(protocol)
    call_protocol_method(protocol, lambda: protocol.mail('foo@bar.com'),
                         b'MAIL FROM:<foo@bar.com> BODY=8BITMIME\r\n')
    pytest.raises(SMTPErrorResponse, feed_bytes, protocol, b'530 Authentication required\r\n').\
        match('530 Authentication required')


def test_noop(protocol):
    exchange_greetings(protocol)
    call_protocol_method(protocol, protocol.noop, b'NOOP\r\n')
    feed_bytes(protocol, b'250 OK\r\n', 250, 'OK', ClientState.ready)


def test_start_tls(protocol):
    exchange_greetings(protocol)
    call_protocol_method(protocol, protocol.start_tls, b'STARTTLS\r\n')
    feed_bytes(protocol, b'220 OK\r\n', 220, 'OK', ClientState.greeting_received)


def test_start_tls_missing_extension(protocol):
    exchange_greetings(protocol, esmtp=False)
    pytest.raises(SMTPMissingExtension, protocol.start_tls).\
        match('This operation requires the STARTTLS extension but the server does not support it')


def test_quit(protocol):
    exchange_greetings(protocol)
    call_protocol_method(protocol, protocol.quit, b'QUIT\r\n')
    feed_bytes(protocol, b'221 OK\r\n', 221, 'OK', ClientState.finished)


def test_auth_plain(protocol):
    exchange_greetings(protocol)

    call_protocol_method(protocol, lambda: protocol.authenticate('PLAIN', 'dGVzdDpwYXNz'),
                         b'AUTH PLAIN dGVzdDpwYXNz\r\n')
    feed_bytes(protocol, b'235 Authentication successful\r\n', 235, 'Authentication successful',
               ClientState.authenticated)


def test_server_invalid_input(protocol):
    exc = pytest.raises(SMTPProtocolViolation, feed_bytes, protocol, b'BLAH foobar\r\n')
    exc.match('Invalid input: BLAH foobar')


def test_server_invalid_continuation(protocol):
    feed_bytes(protocol, b'220-hello\r\n')
    exc = pytest.raises(SMTPProtocolViolation, feed_bytes, protocol, b'230 hello\r\n')
    exc.match('Expected code 220, got 230 instead')


def test_server_invalid_status_code(protocol):
    exc = pytest.raises(SMTPProtocolViolation, feed_bytes, protocol, b'600 hello\r\n')
    exc.match('Unexpected response: 600 hello')


@pytest.mark.parametrize('error_code', [504, 550])
def test_ehlo_error(protocol, error_code):
    feed_bytes(protocol, b'220 foo.bar SMTP service ready\r\n', 220, 'foo.bar SMTP service ready',
               ClientState.greeting_received)
    call_protocol_method(protocol, lambda: protocol.send_greeting('foo.bar'), b'EHLO foo.bar\r\n')
    pytest.raises(SMTPErrorResponse, feed_bytes, protocol, f'{error_code} Error\r\n'.encode()).\
        match(f'{error_code} Error')


@pytest.mark.parametrize('error_code', [502, 504, 550])
def test_helo_error(protocol, error_code):
    feed_bytes(protocol, b'220 foo.bar SMTP service ready\r\n', 220, 'foo.bar SMTP service ready',
               ClientState.greeting_received)
    call_protocol_method(protocol, lambda: protocol.send_greeting('foo.bar'), b'EHLO foo.bar\r\n')
    feed_bytes(protocol, b'500 unrecognized command\r\n')
    assert protocol.get_outgoing_data() == b'HELO foo.bar\r\n'
    pytest.raises(SMTPErrorResponse, feed_bytes, protocol, f'{error_code} Error\r\n'.encode()).\
        match(f'{error_code} Error')


@pytest.mark.parametrize('error_code', [451, 452, 455, 503, 550, 553, 552, 555])
def test_mail_error(protocol, error_code):
    exchange_greetings(protocol)
    call_protocol_method(protocol, lambda: protocol.mail('foo@bar'),
                         b'MAIL FROM:<foo@bar> BODY=8BITMIME\r\n')
    pytest.raises(SMTPErrorResponse, feed_bytes, protocol, f'{error_code} Error\r\n'.encode()).\
        match(f'{error_code} Error')


@pytest.mark.parametrize('error_code', [450, 451, 452, 455, 503, 550, 551, 552, 553, 555])
def test_rcpt_error(protocol, error_code):
    exchange_greetings(protocol)
    call_protocol_method(protocol, lambda: protocol.mail('foo@bar'),
                         b'MAIL FROM:<foo@bar> BODY=8BITMIME\r\n')
    feed_bytes(protocol, b'250 OK\r\n', 250, 'OK')
    call_protocol_method(protocol, lambda: protocol.recipient('foo@bar'), b'RCPT TO:<foo@bar>\r\n')
    pytest.raises(SMTPErrorResponse, feed_bytes, protocol, f'{error_code} Error\r\n'.encode()).\
        match(f'{error_code} Error')


@pytest.mark.parametrize('error_code', [450, 451, 452, 503, 550, 552, 554])
def test_start_data_error(protocol, error_code):
    exchange_greetings(protocol)
    call_protocol_method(protocol, lambda: protocol.mail('foo@bar'),
                         b'MAIL FROM:<foo@bar> BODY=8BITMIME\r\n')
    feed_bytes(protocol, b'250 OK\r\n', 250, 'OK')
    call_protocol_method(protocol, lambda: protocol.recipient('foo@bar'), b'RCPT TO:<foo@bar>\r\n')
    feed_bytes(protocol, b'250 OK\r\n', 250, 'OK')
    call_protocol_method(protocol, protocol.start_data, b'DATA\r\n')
    pytest.raises(SMTPErrorResponse, feed_bytes, protocol, f'{error_code} Error\r\n'.encode()).\
        match(f'{error_code} Error')


@pytest.mark.parametrize('error_code', [432, 454, 500, 534, 535, 538])
def test_auth_error(protocol, error_code):
    exchange_greetings(protocol)
    call_protocol_method(protocol, lambda: protocol.authenticate('PLAIN', 'dummy'),
                         b'AUTH PLAIN dummy\r\n')
    pytest.raises(SMTPErrorResponse, feed_bytes, protocol, f'{error_code} Error\r\n'.encode()).\
        match(f'{error_code} Error')