from abc import ABCMeta, abstractmethod
from base64 import b64encode


class SMTPCredentialsProvider(metaclass=ABCMeta):
    """Interface for providing credentials for authenticating against SMTP servers."""

    @property
    @abstractmethod
    def mechanism(self) -> str:
        """The name of the authentication mechanism (e.g. ``PLAIN`` or ``GSSAPI``)."""

    @abstractmethod
    def get_credentials(self) -> str:
        """Retrieve the credentials to be passed to the server."""


class PlainCredentialsProvider(SMTPCredentialsProvider):
    """
    Authenticates against the server using a username/password combination.

    :param username: user name to authenticate as
    :param password: password to authenticate with
    """

    def __init__(self, username: str, password: str):
        joined = (username + ':' + password).encode('utf-8')
        self._encoded = b64encode(joined).decode('ascii')

    @property
    def mechanism(self) -> str:
        return 'PLAIN'

    def get_credentials(self) -> str:
        return self._encoded


class OAuth2CredentialsProvider(SMTPCredentialsProvider):
    """
    Authenticates against the server using an OAUTH2 access token.

    The user is responsible for obtaining the access token.

    :param username: the user name to authenticate as
    :param token: the access token to authenticate with
    """

    def __init__(self, username: str, token: str):
        self._encoded = b64encode(
            f'user={username}\x01auth=Bearer {token}\x01\x01'.encode('utf-8')).decode('ascii')

    @property
    def mechanism(self) -> str:
        return 'XOAUTH2'

    def get_credentials(self) -> str:
        return self._encoded
