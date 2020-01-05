from abc import ABCMeta, abstractmethod
from base64 import b64encode


class SMTPCredentialsProvider(metaclass=ABCMeta):
    @property
    @abstractmethod
    def mechanism(self) -> str:
        """The name of the authentication mechanism (e.g. ``PLAIN`` or ``GSSAPI``)."""

    @abstractmethod
    async def get_credentials(self) -> str:
        """Retrieve the credentials to be passed to the server."""


class PlainCredentialsProvider(SMTPCredentialsProvider):
    def __init__(self, username: str, password: str):
        joined = (username + ':' + password).encode('utf-8')
        self._encoded = b64encode(joined).decode('ascii')

    @property
    def mechanism(self) -> str:
        return 'PLAIN'

    async def get_credentials(self) -> str:
        return self._encoded


class OAuth2CredentialsProvider(SMTPCredentialsProvider):
    def __init__(self, username: str, token: str):
        self._encoded = b64encode(
            f'user={username}\x01auth=Bearer {token}\x01\x01'.encode('utf-8')).decode('ascii')

    @property
    def mechanism(self) -> str:
        return 'XOAUTH2'

    async def get_credentials(self) -> str:
        return self._encoded
