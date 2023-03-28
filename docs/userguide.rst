Using the concrete I/O implementations
======================================

.. py:currentmodule:: smtpproto.client

In addition to the sans-io protocol implementation, this library also provides both an
asynchronous and a synchronous SMTP client class (:class:`~AsyncSMTPClient` and
:class:`~SyncSMTPClient`, respectively).

Most SMTP servers, however, require some form of authentication. While it would be
unfeasible to provide solutions for every possible situation, the examples below should
cover some very common cases and should give you a general idea of how to work with SMTP
authentication.

For the OAuth2 examples (further below), you need to install a couple dependencies:

* aiohttp_
* PyJWT_

.. _aiohttp: https://pypi.org/project/aiohttp/
.. _PyJWT: https://pypi.org/project/pyjwt/


Sending mail via a local SMTP server
------------------------------------

.. code-block:: python3

    from email.message import EmailMessage

    import anyio
    from smtpproto.auth import PlainAuthenticator
    from smtpproto.client import AsyncSMTPClient


    async def main():
        async with AsyncSMTPClient(host='localhost', port=25) as client:
            await client.send_message(message)

    # If your SMTP server requires basic authentication, this is where you enter that
    # info
    authenticator = PlainAuthenticator(username='myuser', password='mypassword')

    # The message you want to send
    message = EmailMessage()
    message['From'] = 'my.name@mydomain.com'
    message['To'] = 'somebody@somewhere'
    message['Subject'] = 'Test from smtpproto'
    message.set_content('This is a test.')

    # Actually sends the message by running main()
    anyio.run(main)


Sending mail via Gmail
----------------------

The `developer documentation`_ for the G Suite describes how to use the XOAUTH2
mechanism for authenticating against the Gmail SMTP server. The following is a practical
example of how to extend the :class:`~.auth.OAuth2Authenticator` class to obtain an
access token and use it to send an email via Gmail.

The following example assumes the presence of an existing `G Suite service account`_
authorized to send email via SMTP (using the ``https://mail.google.com/`` scope).

.. code-block:: python3

    from datetime import datetime, timedelta
    from email.message import EmailMessage

    import aiohttp
    import jwt

    import anyio
    from smtpproto.auth import OAuth2Authenticator
    from smtpproto.client import AsyncSMTPClient


    class GMailAuthenticator(OAuth2Authenticator):
        def __init__(self, username: str, client_id: str, private_key: str):
            super().__init__(username)
            self.client_id = client_id
            self.private_key = private_key

        async def get_token_async(self):
            webtoken = jwt.encode({
                'iss': self.client_id,
                'scope': 'https://mail.google.com/',
                'aud': 'https://oauth2.googleapis.com/token',
                'exp': datetime.utcnow() + timedelta(minutes=1),
                'iat': datetime.utcnow(),
                'sub': self.username
            }, self.private_key, algorithm='RS256')

            data = {
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': webtoken.decode('ascii')
            }
            async with aiohttp.request(
                'POST',
                'https://oauth2.googleapis.com/token',
                data=data,
                raise_for_status=True
            ) as response:
                json_body = await response.json()

            return json_body['access_token'], json_body["expires_in"]


    async def main():
        async with AsyncSMTPClient(
            host='smtp.gmail.com', authenticator=authenticator
        ) as client:
            await client.send_message(message)

    # Your gmail user name
    me = 'my.name@gmail.com'

    # Service account ID and private key – these have to be obtained from Gmail
    client_id = 'yourserviceaccount@yourdomain.iam.gserviceaccount.com'
    private_key = '-----BEGIN PRIVATE KEY-----\n...-----END PRIVATE KEY-----\n'
    authenticator = GMailAuthenticator(
        username=me, client_id=client_id, private_key=private_key
    )

    # The message you want to send
    message = EmailMessage()
    message['From'] = me
    message['To'] = 'somebody@somewhere'
    message['Subject'] = 'Test from smtpproto'
    message.set_content('This is a test.')

    # Actually sends the message by running main()
    anyio.run(main)

.. _developer documentation: https://developers.google.com/gmail/imap/xoauth2-protocol
.. _G Suite service account: https://support.google.com/a/answer/7378726?hl=en


Sending mail via Office 365
---------------------------

.. warning:: It is currently not clear what actual permissions the service account
    requires. As such, this example *should* work but has never been successfully
    tested.

The following example assumes the presence of a registered `Azure application`_
authorized to send email via SMTP (using the ``SMTP.Send`` scope). It uses the
`device code flow`_ to obtain an access token.

In order for the device code flow to work for the registered application, the following
settings must be in place:

* The redirect URI for the application must be
  ``https://login.microsoftonline.com/common/oauth2/nativeclient``
* The ``Treat application as a public client`` option must be enabled
* The ``SMTP.Send`` permission from ``Microsoft Graph`` must be added in the configured
  permissions

In addition, your Azure AD must not have `Security defaults`_ enabled.

.. code-block:: python3

    from email.message import EmailMessage

    import aiohttp

    import anyio
    from smtpproto.auth import OAuth2Authenticator
    from smtpproto.client import AsyncSMTPClient


    class AzureAuthenticator(OAuth2Authenticator):
        def __init__(
            self, username: str, tenant_id, client_id: str, client_secret: str
        ):
            super().__init__(username)
            self.tenant_id = tenant_id
            self.client_id = client_id
            self.client_secret = client_secret

        async def get_token_async(self):
            data = {'client_id': self.client_id,
                    'scope': 'https://outlook.office.com/SMTP.Send',
                    'client_secret': self.client_secret,
                    'grant_type': 'client_credentials'}
            async with aiohttp.request(
                'POST',
                f'https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token',
                data=data,
                raise_for_status=True
            ) as response:
                json_body = await response.json()

            return json_body['access_token'], json_body["expires_in"]


    async def main():
        async with AsyncSMTPClient(
            host='smtp.office365.com', authenticator=authenticator
        ) as client:
            await client.send_message(message)

    # Your Office 365 username/email address
    me = 'my.name@office365.com'

    # Application (client) ID and secret – these have to be obtained from the Azure
    # portal
    tenant_id = '11111111-1111-1111-1111-111111111111'
    client_id = '11111111-1111-1111-1111-111111111111'
    client_secret = '...'
    authenticator = AzureAuthenticator(
        username=me,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )

    # The message you want to send
    message = EmailMessage()
    message['From'] = me
    message['To'] = 'somebody@somewhere'
    message['Subject'] = 'Test from smtpproto'
    message.set_content('This is a test.')

    # Actually sends the message by running main()
    anyio.run(main)

.. _Azure application: https://docs.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth#register-your-application
.. _device code flow: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
.. _Security defaults: https://docs.microsoft.com/fi-fi/azure/active-directory/fundamentals/concept-fundamentals-security-defaults
