from email.message import EmailMessage
from typing import cast

import anyio
import httpx
from smtpproto.auth import JSONWebToken, OAuth2Authenticator
from smtpproto.client import AsyncSMTPClient


class EntraIDAuthenticator(OAuth2Authenticator):
    def __init__(
        self, username: str, tenant_id: str, client_id: str, client_secret: str
    ):
        super().__init__(username)
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    async def get_token(self) -> JSONWebToken:
        async with httpx.AsyncClient() as http:
            response = await http.post(
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": self.client_id,
                    "scope": "https://outlook.office.com/SMTP.Send",
                    "client_secret": self.client_secret,
                    "grant_type": "client_credentials",
                },
            )
            response.raise_for_status()
            return cast(JSONWebToken, await response.json())


async def main() -> None:
    async with AsyncSMTPClient(
        host="smtp.office365.com", authenticator=authenticator
    ) as client:
        await client.send_message(message)


authenticator = EntraIDAuthenticator(
    # Your Office 365 username/email address
    username="my.name@office365.com",
    # Tenant ID, application (client) ID and secret – these have to be obtained from the
    # Azure portal
    tenant_id="11111111-1111-1111-1111-111111111111",
    client_id="11111111-1111-1111-1111-111111111111",
    client_secret="...",
)

# The message you want to send
message = EmailMessage()
message["From"] = "my.name@office365.com"
message["To"] = "somebody@somewhere"
message["Subject"] = "Test from smtpproto"
message.set_content("This is a test.")

# Actually sends the message by running main()
anyio.run(main)
