from __future__ import annotations

import ssl
from collections import defaultdict
from collections.abc import Callable, Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing, contextmanager
from email.headerregistry import Address
from email.message import EmailMessage
from socket import socket
from typing import Any

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Sink
from aiosmtpd.smtp import SMTP, AuthResult, Envelope, Session
from anyio import create_task_group
from smtpproto.auth import PlainAuthenticator
from smtpproto.client import AsyncSMTPClient, SyncSMTPClient
from smtpproto.protocol import SMTPException

pytestmark = pytest.mark.anyio


class DummyController(Controller):
    def __init__(
        self,
        handler: Any,
        factory: Callable[..., SMTP] = SMTP,
        hostname: str | None = None,
        port: int = 0,
        *,
        ready_timeout: float = 1.0,
        ssl_context: ssl.SSLContext | None = None,
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

    def factory(self) -> SMTP:
        return self.__factory(
            self.handler, hostname=self.hostname, tls_context=self.__ssl_context
        )


@contextmanager
def start_server(
    *,
    ssl_context: ssl.SSLContext | None = None,
    factory: Callable[..., SMTP] = SMTP,
    handler: Any = Sink,
) -> Generator[tuple[str, int], Any, None]:
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


@pytest.fixture
def message() -> EmailMessage:
    message = EmailMessage()
    message["From"] = Address("Foo Bar", "foo.bar", "baz.com")
    message["To"] = ["test1@example.org"]
    message["Cc"] = ["test2@example.org"]
    message["Bcc"] = ["test3@example.org"]
    message["Resent-To"] = ["test4@example.org"]
    message["Resent-Cc"] = ["test5@example.org"]
    message["Resent-Bcc"] = ["test6@example.org"]
    message["Subject"] = "Unicöde string"
    return message


class TestAsyncClient:
    @pytest.mark.parametrize("use_tls", [False, True], ids=["notls", "tls"])
    async def test_send_mail(
        self,
        client_context: ssl.SSLContext,
        server_context: ssl.SSLContext,
        use_tls: bool,
        message: EmailMessage,
    ) -> None:
        received_recipients = []
        received_content = b""

        class Handler:
            async def handle_RCPT(
                self,
                server: SMTP,
                session: Session,
                envelope: Envelope,
                address: str,
                rcpt_options: list[str],
            ) -> str:
                received_recipients.append(address)
                envelope.rcpt_tos.append(address)
                envelope.rcpt_options.extend(rcpt_options)
                return "250 OK"

            async def handle_DATA(
                self, server: SMTP, session: Session, envelope: Envelope
            ) -> str:
                nonlocal received_content
                received_content = envelope.original_content or b""
                return "250 OK"

        with start_server(
            ssl_context=server_context if use_tls else None, handler=Handler()
        ) as (host, port):
            client = AsyncSMTPClient(host=host, port=port, ssl_context=client_context)
            await client.send_message(message)

        assert received_recipients == [
            f"test{index}@example.org" for index in range(1, 7)
        ]
        assert b"To: test1@example.org" in received_content
        assert b"Cc: test2@example.org" in received_content
        assert b"Resent-To: test4@example.org" in received_content
        assert b"Resent-Cc: test5@example.org" in received_content
        assert b"Bcc:" not in received_content
        assert b"Resent-Bcc:" not in received_content

    async def test_concurrency(self, message: EmailMessage) -> None:
        received_recipients: dict[str, int] = defaultdict(lambda: 0)
        received_contents: list[bytes] = []

        class Handler:
            async def handle_RCPT(
                self,
                server: SMTP,
                session: Session,
                envelope: Envelope,
                address: str,
                rcpt_options: list[str],
            ) -> str:
                received_recipients[address] += 1
                envelope.rcpt_tos.append(address)
                envelope.rcpt_options.extend(rcpt_options)
                return "250 OK"

            async def handle_DATA(
                self, server: SMTP, session: Session, envelope: Envelope
            ) -> str:
                received_contents.append(envelope.original_content or b"")
                return "250 OK"

        with start_server(handler=Handler()) as (host, port):
            client = AsyncSMTPClient(host=host, port=port)

            async def send_multiple_messages(count: int) -> None:
                async with client.connect() as session:
                    for _ in range(count):
                        await session.send_message(message)

            async with create_task_group() as tg:
                for _ in range(10):
                    tg.start_soon(send_multiple_messages, 10)

        for index in range(1, 7):
            assert received_recipients[f"test{index}@example.org"] == 100

        assert len(received_contents) == 100

    async def test_no_esmtp_support(self) -> None:
        class NoESMTP(SMTP):
            async def smtp_EHLO(self, hostname: str) -> None:
                await self.push("500 Unknown command")

        with start_server(factory=NoESMTP) as (host, port):
            client = AsyncSMTPClient(host=host, port=port)
            async with client.connect():
                pass

    @pytest.mark.parametrize("success", [True, False], ids=["success", "failure"])
    async def test_auth_plain(
        self,
        client_context: ssl.SSLContext,
        server_context: ssl.SSLContext,
        success: bool,
    ) -> None:
        class AuthCapableSMTP(SMTP):
            async def auth_PLAIN(self, _: Any, args: list[str]) -> AuthResult:
                expected = "AHVzZXJuYW1lAHBhc3N3b3Jk"
                if args[1] == expected and success:
                    return AuthResult(success=True)
                else:
                    return AuthResult(success=False, handled=False)

        with ExitStack() as stack:
            host, port = stack.enter_context(
                start_server(ssl_context=server_context, factory=AuthCapableSMTP)
            )
            if not success:
                stack.enter_context(pytest.raises(SMTPException))

            authenticator = PlainAuthenticator("username", "password")
            client = AsyncSMTPClient(
                host=host,
                port=port,
                ssl_context=client_context,
                authenticator=authenticator,
            )
            async with client.connect():
                pass


class TestSyncClient:
    @pytest.mark.parametrize("use_tls", [False, True], ids=["notls", "tls"])
    def test_send_mail(
        self,
        client_context: ssl.SSLContext,
        server_context: ssl.SSLContext,
        use_tls: bool,
    ) -> None:
        message = EmailMessage()
        message["From"] = Address("Foo Bar", "foo.bar", "baz.com")
        message["To"] = ["test@example.org"]
        message["Cc"] = ["test2@example.org"]
        message["Subject"] = "Unicöde string"
        with start_server(ssl_context=server_context if use_tls else None) as (
            host,
            port,
        ):
            client = SyncSMTPClient(host=host, port=port, ssl_context=client_context)
            client.send_message(message)

    def test_concurrency(self, message: EmailMessage) -> None:
        received_recipients: dict[str, int] = defaultdict(lambda: 0)
        received_contents: list[bytes] = []

        class Handler:
            async def handle_RCPT(
                self,
                server: SMTP,
                session: Session,
                envelope: Envelope,
                address: str,
                rcpt_options: list[str],
            ) -> str:
                received_recipients[address] += 1
                envelope.rcpt_tos.append(address)
                envelope.rcpt_options.extend(rcpt_options)
                return "250 OK"

            async def handle_DATA(
                self, server: SMTP, session: Session, envelope: Envelope
            ) -> str:
                received_contents.append(envelope.original_content or b"")
                return "250 OK"

        with start_server(handler=Handler()) as (host, port):
            client = SyncSMTPClient(host=host, port=port)

            def send_multiple_messages(count: int) -> None:
                with client.connect() as session:
                    for _ in range(count):
                        session.send_message(message)

            with ThreadPoolExecutor() as executor:
                for _ in range(10):
                    executor.submit(send_multiple_messages, 10)

        for index in range(1, 7):
            assert received_recipients[f"test{index}@example.org"] == 100

        assert len(received_contents) == 100

    def test_no_esmtp_support(self) -> None:
        class NoESMTP(SMTP):
            async def smtp_EHLO(self, hostname: str) -> None:
                await self.push("500 Unknown command")

        with start_server(factory=NoESMTP) as (host, port):
            client = SyncSMTPClient(host=host, port=port)
            with client.connect():
                pass

    @pytest.mark.parametrize("success", [True, False], ids=["success", "failure"])
    def test_auth_plain(
        self,
        client_context: ssl.SSLContext,
        server_context: ssl.SSLContext,
        success: bool,
    ) -> None:
        class AuthCapableSMTP(SMTP):
            async def auth_PLAIN(self, _: Any, args: list[str]) -> AuthResult:
                expected = "AHVzZXJuYW1lAHBhc3N3b3Jk"
                if args[1] == expected and success:
                    return AuthResult(success=True)
                else:
                    return AuthResult(success=False, handled=False)

        with ExitStack() as stack:
            host, port = stack.enter_context(
                start_server(ssl_context=server_context, factory=AuthCapableSMTP)
            )
            if not success:
                stack.enter_context(pytest.raises(SMTPException))

            authenticator = PlainAuthenticator("username", "password")
            client = SyncSMTPClient(
                host=host,
                port=port,
                ssl_context=client_context,
                authenticator=authenticator,
            )
            with client.connect():
                pass
