Developing new I/O implementations
==================================

.. py:currentmodule:: smtpproto.protocol

The procedure to using the SMTP client protocol state machine to communicate with an
SMTP server is as follows:

#. Create the state machine (:class:`~SMTPClientProtocol`)
#. Connect to the SMTP server using your chosen I/O backend

Sending commands and receiving responses:

#. Call the appropriate method on the state machine
#. Retrieve the outgoing data with :meth:`~SMTPClientProtocol.get_outgoing_data`
#. Use your I/O backend to send that data to the server
#. Use your I/O backend to receive the response data
#. Feed the response data to the state machine using
   :meth:`~SMTPClientProtocol.feed_bytes`
#. If the return value is an :class:`~SMTPResponse` (and not ``None``), process the
   response as appropriate. You can use :meth:`~SMTPResponse.is_error` as a convenience
   to check if the response code means there was an error.

Establishing a TLS session after connection (optional):

#. Check if the feature is supported by the server (``STARTTLS`` is in
   :attr:`~SMTPClientProtocol.extensions`)
#. Send the ``STARTTLS`` command using :meth:`~SMTPClientProtocol.start_tls`
#. Use your I/O backend to do the TLS handshake in client mode
   (:meth:`~ssl.SSLContext.wrap_socket` or whatever you prefer)
#. Proceed with the session as usual

Developing new authenticators
=============================

.. py:currentmodule:: smtpproto.auth

To add support for a new authentication mechanism, you can create a new class that
inherits from either :class:`~SMTPAuthenticator` or one of its subclasses. This subclass
needs to implement:

* The :attr:`~SMTPAuthenticator.mechanism` property
* The :meth:`~SMTPAuthenticator.authenticate` method

The ``mechanism`` property should return the name of the authentication mechanism (in
upper case letters). It is used to send the initial ``AUTH`` command. If ``mechanism``
returns ``FOOBAR``, the client would send the command ``AUTH FOOBAR``.

The ``authenticate`` method should return an asynchronous generator that yields strings.
If the generator yields a nonempty string on the first call, it is added to the ``AUTH``
command. For example, given the following code, the client would authenticate with the
command ``AUTH FOOBAR mysecret``::

    from smtpproto.auth import SMTPAuthenticator

    class MyAuthenticator(SMTPAuthenticator):
        @property
        def mechanism(self) -> str:
            return 'FOOBAR'

        async def authenticate(self) -> AsyncGenerator[str, str]:
            yield 'mysecret'

For mechanisms such as ``LOGIN`` that involve more rounds of information exchange, the
generator typically yields an empty string first. It will then be sent back the server
response text as the ``yield`` result. The authenticator will then yield its own
response, and so forth. See the source code of the :class:`~LoginAuthenticator` class
for an example.
