from __future__ import annotations

import time
from abc import ABCMeta, abstractmethod
from base64 import b64decode, b64encode
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import TypedDict


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


class JSONWebToken(TypedDict):
    access_token: str
    expires_in: float


class OAuth2Authenticator(SMTPAuthenticator):
    """
    Authenticates against the server using OAUTH2.

    In order to use this authenticator, you must subclass it and implement the
    :meth:`get_token` method.

    :param username: the user name to authenticate as
    :param grace_period: number of seconds prior to token expiration to get a new one
    """

    _stored_token: str | None = None
    _expires_at: float | None = None

    def __init__(self, username: str, *, grace_period: float = 600):
        self.username: str = username
        self.grace_period = grace_period

    @property
    def mechanism(self) -> str:
        return "XOAUTH2"

    async def authenticate(self) -> AsyncGenerator[str, str]:
        # Don't request a new token unless it has expired or is close to expiring
        if (
            self._stored_token
            and self._expires_at
            and time.monotonic() - self._expires_at
        ):
            token = self._stored_token
        else:
            jwt = await self.get_token()
            self._stored_token = token = jwt["access_token"]
            self._expires_at = time.monotonic() + jwt["expires_in"] - self.grace_period

        auth_string = f"user={self.username}\x01auth=Bearer {token}\x01\x01"
        yield b64encode(auth_string.encode("utf-8")).decode("ascii")

    @abstractmethod
    async def get_token(self) -> JSONWebToken:
        """
        Obtain a new access token.

        This method will be called only when there either is no cached token, or the
        cached token is expired or nearing expiration. You can also use
        :meth:`clear_cached_token` to manually erase the cached token. The
        ``expires_in`` field in the returned dict is the number of seconds after which
        the token will expire.

        .. note:: If the backing server does not provide a value for ``expires_in``,
            the implementor must fill in the value by other means.

        :return: a dict containing the ``access_token`` and ``expires_in`` fields
        """

    def clear_cached_token(self) -> None:
        """Clear the previously stored token, if any."""
        self._stored_token = self._expires_at = None
