from email.message import EmailMessage

import anyio

from smtpproto.auth import PlainAuthenticator
from smtpproto.client import AsyncSMTPClient


async def main() -> None:
    client = AsyncSMTPClient(host="localhost", port=25, authenticator=authenticator)
    await client.send_message(message)


# If your SMTP server requires basic authentication, this is where you enter that
# info
authenticator = PlainAuthenticator(username="myuser", password="mypassword")

# The message you want to send
message = EmailMessage()
message["From"] = "my.name@mydomain.com"
message["To"] = "somebody@somewhere"
message["Subject"] = "Test from smtpproto"
message.set_content("This is a test.")

# Actually sends the message by running main()
anyio.run(main)
