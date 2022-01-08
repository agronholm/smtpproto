import ssl
import sys
import threading
from contextlib import ExitStack, contextmanager
from email.headerregistry import Address
from email.message import EmailMessage
from traceback import print_stack
from typing import Optional

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink
from aiosmtpd.smtp import SMTP, syntax

from smtpproto.auth import PlainAuthenticator
from smtpproto.client import AsyncSMTPClient, SyncSMTPClient
from smtpproto.protocol import SMTPException

pytestmark = pytest.mark.anyio


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


class TestAsyncClient:
    @pytest.mark.parametrize('use_tls', [False, True], ids=['notls', 'tls'])
    async def test_send_mail(self, client_context, server_context, use_tls):
        message = EmailMessage()
        message['From'] = Address('Foo Bar', 'foo.bar', 'baz.com')
        message['To'] = ['test@example.org']
        message['Cc'] = ['test2@example.org']
        message['Subject'] = 'Unicöde string'
        with start_server(ssl_context=server_context if use_tls else None) as (host, port):
            async with AsyncSMTPClient(host=host, port=port, ssl_context=client_context) as client:
                await client.send_message(message)

    async def test_no_esmtp_support(self):
        class NoESMTP(SMTP):
            async def smtp_EHLO(self, hostname):
                await self.push('500 Unknown command')
                return

        with start_server(factory=NoESMTP) as (host, port):
            async with AsyncSMTPClient(host=host, port=port):
                pass

    @pytest.mark.parametrize('use_tls', [False, True], ids=['notls', 'tls'])
    @pytest.mark.parametrize('success', [True, False], ids=['success', 'failure'])
    async def test_auth_plain(self, client_context, server_context, use_tls, success):
        class AuthCapableHandler:
            @staticmethod
            async def handle_EHLO(server, session, envelope, hostname):
                await server.push('250-AUTH PLAIN')
                return '250 HELP'

        class AuthCapableSMTP(SMTP):
            @syntax('AUTH <secret>')
            async def smtp_AUTH(self, arg):
                credentials = arg.split(' ')[1]
                expected = 'AHVzZXJuYW1lAHBhc3N3b3Jk'
                if credentials == expected and success:
                    await self.push('235 Authentication successful')
                else:
                    await self.push('535 Invalid credentials')

        authenticator = PlainAuthenticator('username', 'password')
        with start_server(ssl_context=server_context if use_tls else None, factory=AuthCapableSMTP,
                          handler=AuthCapableHandler) as (host, port):
            with ExitStack() if success else pytest.raises(SMTPException):
                async with AsyncSMTPClient(host=host, port=port, ssl_context=client_context,
                                           authenticator=authenticator):
                    pass


class TestSyncClient:
    @pytest.fixture(autouse=True)
    def print_threads(self):
        yield
        for t in threading.enumerate():
            print(t)

    @pytest.mark.parametrize('use_tls', [False, True], ids=['notls', 'tls'])
    def test_send_mail(self, client_context, server_context, use_tls):
        message = EmailMessage()
        message['From'] = Address('Foo Bar', 'foo.bar', 'baz.com')
        message['To'] = ['test@example.org']
        message['Cc'] = ['test2@example.org']
        message['Subject'] = 'Unicöde string'
        with start_server(ssl_context=server_context if use_tls else None) as (host, port):
            with SyncSMTPClient(host=host, port=port, ssl_context=client_context) as client:
                client.send_message(message)

    def test_no_esmtp_support(self):
        class NoESMTP(SMTP):
            async def smtp_EHLO(self, hostname):
                await self.push('500 Unknown command')
                return

        with start_server(factory=NoESMTP) as (host, port):
            with SyncSMTPClient(host=host, port=port):
                pass

    @pytest.mark.parametrize('use_tls', [False, True], ids=['notls', 'tls'])
    @pytest.mark.parametrize('success', [True, False], ids=['success', 'failure'])
    def test_auth_plain(self, client_context, server_context, use_tls, success):
        class AuthCapableHandler:
            @staticmethod
            async def handle_EHLO(server, session, envelope, hostname):
                await server.push('250-AUTH PLAIN')
                return '250 HELP'

        class AuthCapableSMTP(SMTP):
            @syntax('AUTH <secret>')
            async def smtp_AUTH(self, arg):
                credentials = arg.split(' ')[1]
                expected = 'AHVzZXJuYW1lAHBhc3N3b3Jk'
                if credentials == expected and success:
                    await self.push('235 Authentication successful')
                else:
                    await self.push('535 Invalid credentials')

        authenticator = PlainAuthenticator('username', 'password')
        with start_server(ssl_context=server_context if use_tls else None, factory=AuthCapableSMTP,
                          handler=AuthCapableHandler) as (host, port):
            with ExitStack() if success else pytest.raises(SMTPException):
                with SyncSMTPClient(host=host, port=port, ssl_context=client_context,
                                    authenticator=authenticator):
                    pass

        for thread_id, frame in sys._current_frames().items():
            print('Thread', thread_id)
            print_stack(frame)
