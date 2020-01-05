import logging
import ssl
from contextlib import contextmanager, ExitStack
from email.headerregistry import Address
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink
from aiosmtpd.smtp import SMTP, syntax

from smtpproto.async_auth import PlainCredentialsProvider
from smtpproto.async_client import AsyncSMTPClient
from smtpproto.protocol import SMTPError


class DummyController(Controller):
    def __init__(self, handler, factory=SMTP, hostname=None, port=0, *, ready_timeout=1.0,
                 enable_SMTPUTF8=True, ssl_context=None):
        super().__init__(handler, hostname=hostname, port=port, ready_timeout=ready_timeout,
                         enable_SMTPUTF8=enable_SMTPUTF8, ssl_context=None)
        self.__factory = factory
        self.__ssl_context = ssl_context

    def factory(self):
        return self.__factory(self.handler, enable_SMTPUTF8=self.enable_SMTPUTF8,
                              hostname=self.hostname, tls_context=self.__ssl_context)


@contextmanager
def start_server(*, ssl_context: Optional[ssl.SSLContext] = None, factory=SMTP,
                 handler: type = Sink):
    controller = DummyController(handler, factory=factory, hostname='localhost',
                                 ssl_context=ssl_context)
    controller.start()
    port = controller.server.sockets[0].getsockname()[1]
    yield controller.hostname, port
    controller.stop()


@pytest.fixture(params=[False, True], ids=['notls', 'tls'])
def server_context(request):
    if request.param:
        server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_context.load_cert_chain(certfile=str(Path(__file__).with_name('cert.pem')),
                                       keyfile=str(Path(__file__).with_name('key.pem')))
        return server_context
    else:
        return None


@pytest.fixture(scope='module')
def client_context():
    client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    client_context.load_verify_locations(cafile=str(Path(__file__).with_name('cert.pem')))
    return client_context


@pytest.mark.anyio
async def test_send_mail(caplog, client_context, server_context):
    caplog.set_level(logging.DEBUG)
    message = EmailMessage()
    message['From'] = Address('Foo Bar', 'foo.bar', 'baz.com')
    message['To'] = ['test@example.org']
    message['Cc'] = ['test2@example.org']
    message['Subject'] = 'Unicöde string'
    with start_server(ssl_context=server_context) as (host, port):
        async with AsyncSMTPClient(host=host, port=port, ssl_context=client_context) as client:
            await client.send_message(message)


@pytest.mark.anyio
async def test_no_esmtp_support(caplog):
    class NoESMTP(SMTP):
        async def smtp_EHLO(self, hostname):
            await self.push('500 Unknown command')
            return

    caplog.set_level(logging.DEBUG)
    with start_server(factory=NoESMTP) as (host, port):
        async with AsyncSMTPClient(host=host, port=port):
            pass


@pytest.mark.parametrize('success', [True, False], ids=['success', 'failure'])
@pytest.mark.anyio
async def test_auth_plain(caplog, client_context, server_context, success):
    class AuthCapableHandler:
        @staticmethod
        async def handle_EHLO(server, session, envelope, hostname):
            await server.push('250-AUTH PLAIN')
            return '250 HELP'

    class AuthCapableSMTP(SMTP):
        @syntax('AUTH <secret>')
        async def smtp_AUTH(self, arg):
            credentials = arg.split(' ')[1]
            if credentials == 'dXNlcm5hbWU6cGFzc3dvcmQ=' and success:
                await self.push('235 Authentication successful')
            else:
                await self.push('535 Invalid credentials')

    caplog.set_level(logging.DEBUG)
    credentials_provider = PlainCredentialsProvider('username', 'password')
    with start_server(ssl_context=server_context, factory=AuthCapableSMTP,
                      handler=AuthCapableHandler) as (host, port):
        with ExitStack() if success else pytest.raises(SMTPError):
            async with AsyncSMTPClient(host=host, port=port, ssl_context=client_context,
                                       credentials_provider=credentials_provider):
                pass
