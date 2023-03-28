from __future__ import annotations

import ssl
from contextlib import ExitStack, closing, contextmanager
from email.headerregistry import Address
from email.message import EmailMessage
from socket import socket

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink
from aiosmtpd.smtp import SMTP, AuthResult
from smtpproto.auth import PlainAuthenticator
from smtpproto.client import AsyncSMTPClient, SyncSMTPClient
from smtpproto.protocol import SMTPException

pytestmark = pytest.mark.anyio


class DummyController(Controller):
    def __init__(
        self,
        handler,
        factory=SMTP,
        hostname=None,
        port=0,
        *,
        ready_timeout=1.0,
        ssl_context=None,
    ):
        super().__init__(
            handler,
            hostname=hostname,
            port=port,
            ready_timeout=ready_timeout,
            ssl_context=None,
        )
        self.__factory = factory
        self.__ssl_context = ssl_context

    def factory(self):
        return self.__factory(
            self.handler, hostname=self.hostname, tls_context=self.__ssl_context
        )


@contextmanager
def start_server(
    *, ssl_context: ssl.SSLContext | None = None, factory=SMTP, handler: type = Sink
):
    with closing(socket()) as sock:
        sock.bind(("localhost", 0))
        port = sock.getsockname()[1]

    controller = DummyController(
        handler,
        factory=factory,
        hostname="localhost",
        port=port,
        ssl_context=ssl_context,
    )
    controller.start()
    yield controller.hostname, port
    controller.stop()


class TestAsyncClient:
    @pytest.mark.parametrize("use_tls", [False, True], ids=["notls", "tls"])
    async def test_send_mail(self, client_context, server_context, use_tls):
        message = EmailMessage()
        message["From"] = Address("Foo Bar", "foo.bar", "baz.com")
        message["To"] = ["test@example.org"]
        message["Cc"] = ["test2@example.org"]
        message["Subject"] = "Unicöde string"
        with start_server(ssl_context=server_context if use_tls else None) as (
            host,
            port,
        ):
            async with AsyncSMTPClient(
                host=host, port=port, ssl_context=client_context
            ) as client:
                await client.send_message(message)

    async def test_no_esmtp_support(self):
        class NoESMTP(SMTP):
            async def smtp_EHLO(self, hostname):
                await self.push("500 Unknown command")
                return

        with start_server(factory=NoESMTP) as (host, port):
            async with AsyncSMTPClient(host=host, port=port):
                pass

    @pytest.mark.parametrize("success", [True, False], ids=["success", "failure"])
    async def test_auth_plain(self, client_context, server_context, success):
        class AuthCapableSMTP(SMTP):
            async def auth_PLAIN(self, _, args: list[str]) -> AuthResult:
                expected = "AHVzZXJuYW1lAHBhc3N3b3Jk"
                if args[1] == expected and success:
                    return AuthResult(success=True)
                else:
                    return AuthResult(success=False, handled=False)

        stack = ExitStack()
        host, port = stack.enter_context(
            start_server(ssl_context=server_context, factory=AuthCapableSMTP)
        )
        if not success:
            stack.enter_context(pytest.raises(SMTPException))

        authenticator = PlainAuthenticator("username", "password")
        with stack:
            async with AsyncSMTPClient(
                host=host,
                port=port,
                ssl_context=client_context,
                authenticator=authenticator,
            ):
                pass


class TestSyncClient:
    @pytest.mark.parametrize("use_tls", [False, True], ids=["notls", "tls"])
    def test_send_mail(self, client_context, server_context, use_tls):
        message = EmailMessage()
        message["From"] = Address("Foo Bar", "foo.bar", "baz.com")
        message["To"] = ["test@example.org"]
        message["Cc"] = ["test2@example.org"]
        message["Subject"] = "Unicöde string"
        with start_server(ssl_context=server_context if use_tls else None) as (
            host,
            port,
        ):
            with SyncSMTPClient(
                host=host, port=port, ssl_context=client_context
            ) as client:
                client.send_message(message)

    def test_no_esmtp_support(self):
        class NoESMTP(SMTP):
            async def smtp_EHLO(self, hostname):
                await self.push("500 Unknown command")
                return

        with start_server(factory=NoESMTP) as (host, port):
            with SyncSMTPClient(host=host, port=port):
                pass

    @pytest.mark.parametrize("success", [True, False], ids=["success", "failure"])
    def test_auth_plain(self, client_context, server_context, success):
        class AuthCapableSMTP(SMTP):
            async def auth_PLAIN(self, _, args: list[str]) -> AuthResult:
                expected = "AHVzZXJuYW1lAHBhc3N3b3Jk"
                if args[1] == expected and success:
                    return AuthResult(success=True)
                else:
                    return AuthResult(success=False, handled=False)

        stack = ExitStack()
        host, port = stack.enter_context(
            start_server(ssl_context=server_context, factory=AuthCapableSMTP)
        )
        if not success:
            stack.enter_context(pytest.raises(SMTPException))

        authenticator = PlainAuthenticator("username", "password")
        with stack, SyncSMTPClient(
            host=host,
            port=port,
            ssl_context=client_context,
            authenticator=authenticator,
        ):
            pass
