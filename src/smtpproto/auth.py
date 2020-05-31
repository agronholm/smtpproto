import time
from abc import ABCMeta, abstractmethod
from base64 import b64encode
from dataclasses import dataclass, field
from typing import Tuple, Optional


class SMTPCredentialsProvider(metaclass=ABCMeta):
    """Interface for providing credentials for authenticating against SMTP servers."""

    @property
    @abstractmethod
    def mechanism(self) -> str:
        """The name of the authentication mechanism (e.g. ``PLAIN`` or ``GSSAPI``)."""

    def get_credentials_sync(self) -> str:
        """Retrieve the credentials to be passed to the server."""
        raise NotImplementedError

    async def get_credentials_async(self) -> str:
        """Retrieve the credentials to be passed to the server."""
        import anyio
        return await anyio.run_in_thread(self.get_credentials_sync)


@dataclass
class PlainCredentialsProvider(SMTPCredentialsProvider):
    """
    Authenticates against the server using a username/password combination.

    :param username: user name to authenticate as
    :param password: password to authenticate with
    """

    username: str
    password: str

    @property
    def mechanism(self) -> str:
        return 'PLAIN'

    def get_credentials_sync(self) -> str:
        joined = (self.username + ':' + self.password).encode('utf-8')
        return b64encode(joined).decode('ascii')

    async def get_credentials_async(self) -> str:
        return self.get_credentials_sync()


@dataclass
class OAuth2CredentialsProvider(SMTPCredentialsProvider):
    """
    Authenticates against the server using an OAUTH2 access token.

    The user is responsible for obtaining the access token.

    :param username: the user name to authenticate as
    """

    username: str
    _token: Optional[str] = field(init=False, default=None)
    _expires_at: Optional[float] = field(init=False, default=None)

    def __init__(self, username: str):
        self.username = username

    @property
    def mechanism(self) -> str:
        return 'XOAUTH2'

    def get_credentials_sync(self) -> str:
        token = self.get_token_sync()
        return b64encode(
            f'user={self.username}\x01auth=Bearer {token}\x01\x01'.encode('utf-8')).decode('ascii')

    async def get_credentials_async(self) -> str:
        now = time.monotonic()
        if not self._expires_at or now >= self._expires_at:
            self._token, lifetime = await self.get_token_async()
            self._expires_at = now + lifetime

        auth_string = f'user={self.username}\x01auth=Bearer {self._token}\x01\x01'
        return b64encode(auth_string.encode('utf-8')).decode('ascii')

    def get_token_sync(self) -> Tuple[str, float]:
        """
        Obtain a new access token.

        :return: tuple of (access token, token lifetime in seconds)

        """
        raise NotImplementedError

    async def get_token_async(self) -> Tuple[str, float]:
        """Asynchronous version of :meth:`get_token_sync`."""
        import anyio
        return await anyio.run_in_thread(self.get_token_sync)
