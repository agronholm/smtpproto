from __future__ import annotations

from abc import ABCMeta, abstractmethod
from base64 import b64decode, b64encode
from collections.abc import AsyncGenerator
from dataclasses import dataclass


class SMTPAuthenticator(metaclass=ABCMeta):
    """Interface for providing credentials for authenticating against SMTP servers."""

    @property
    @abstractmethod
    def mechanism(self) -> str:
        """The name of the authentication mechanism (e.g. ``PLAIN`` or ``GSSAPI``)."""

    @abstractmethod
    def authenticate(self) -> AsyncGenerator[str, str]:
        """
        Performs authentication against the SMTP server.

        This method must return an async generator. Any non-empty values the generator
        yields are sent to the server as authentication data. The response messages from
        any 334 responses are sent to the generator.
        """


@dataclass
class PlainAuthenticator(SMTPAuthenticator):
    """
    Authenticates against the server with a username/password combination using the
    PLAIN method.

    :param username: user name to authenticate as
    :param password: password to authenticate with
    :param authorization_id: optional authorization ID
    """

    username: str
    password: str
    authorization_id: str = ""

    @property
    def mechanism(self) -> str:
        return "PLAIN"

    async def authenticate(self) -> AsyncGenerator[str, str]:
        joined = (
            self.authorization_id + "\x00" + self.username + "\x00" + self.password
        ).encode("utf-8")
        yield b64encode(joined).decode("ascii")


@dataclass
class LoginAuthenticator(SMTPAuthenticator):
    """
    Authenticates against the server with a username/password combination using the
    LOGIN method.

    :param username: user name to authenticate as
    :param password: password to authenticate with
    """

    username: str
    password: str

    @property
    def mechanism(self) -> str:
        return "LOGIN"

    async def authenticate(self) -> AsyncGenerator[str, str]:
        for _ in range(2):
            raw_question = yield ""
            question = b64decode(raw_question.encode("ascii")).lower()
            if question == b"username:":
                yield b64encode(self.username.encode("utf-8")).decode("ascii")
            elif question == b"password:":
                yield b64encode(self.password.encode("utf-8")).decode("ascii")
            else:
                raise ValueError(f"Unhandled question: {raw_question}")


class OAuth2Authenticator(SMTPAuthenticator):
    """
    Authenticates against the server using OAUTH2.

    In order to use this authenticator, you must subclass it and implement the
    :meth:`get_token` method.

    :param username: the user name to authenticate as
    """

    def __init__(self, username: str):
        self.username: str = username

    @property
    def mechanism(self) -> str:
        return "XOAUTH2"

    async def authenticate(self) -> AsyncGenerator[str, str]:
        token = await self.get_token()
        auth_string = f"user={self.username}\x01auth=Bearer {token}\x01\x01"
        yield b64encode(auth_string.encode("utf-8")).decode("ascii")

    @abstractmethod
    async def get_token(self) -> str:
        """
        Obtain a new access token.

        Implementors should cache the token and its expiration time and only obtain a
        new one if the old one has expired or is about to.

        :return: the access token
        """
