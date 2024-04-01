from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import cast

import anyio
import httpx
import jwt
from smtpproto.auth import JSONWebToken, OAuth2Authenticator
from smtpproto.client import AsyncSMTPClient


class GMailAuthenticator(OAuth2Authenticator):
    def __init__(self, username: str, client_id: str, private_key: str):
        super().__init__(username)
        self.client_id = client_id
        self.private_key = private_key

    async def get_token(self) -> JSONWebToken:
        webtoken = jwt.encode(
            {
                "iss": self.client_id,
                "scope": "https://mail.google.com/",
                "aud": "https://oauth2.googleapis.com/token",
                "exp": datetime.utcnow() + timedelta(minutes=1),
                "iat": datetime.utcnow(),
                "sub": self.username,
            },
            self.private_key,
            algorithm="RS256",
        )

        async with httpx.AsyncClient() as http:
            response = await http.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": webtoken.decode("ascii"),
                },
            )
            response.raise_for_status()
            return cast(JSONWebToken, await response.json())


async def main() -> None:
    client = AsyncSMTPClient(host="smtp.gmail.com", authenticator=authenticator)
    await client.send_message(message)


authenticator = GMailAuthenticator(
    # Your gmail user name
    username="my.name@gmail.com",
    # Service account ID and private key – these have to be obtained from Gmail
    client_id="yourserviceaccount@yourdomain.iam.gserviceaccount.com",
    private_key="-----BEGIN PRIVATE KEY-----\n...-----END PRIVATE KEY-----\n",
)

# The message you want to send
message = EmailMessage()
message["From"] = "my.name@gmail.com"
message["To"] = "somebody@somewhere"
message["Subject"] = "Test from smtpproto"
message.set_content("This is a test.")

# Actually sends the message by running main()
anyio.run(main)
