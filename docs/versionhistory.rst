Version history
===============

This library adheres to `Semantic Versioning 2.0 <http://semver.org/>`_.

**UNRELEASED**

- Upgraded minimum AnyIO version to 4.4.0

**2.0.0**

- **BACKWARDS INCOMPATIBLE** The concrete client implementations were refactored:

  * ``AsyncSMTPClient`` and ``SyncSMTPClient`` were refactored into "session factories",
    and thus are no longer used as context managers
  * The ``send_message()`` method is now reentrant, as it now creates (and closes) an
    ad-hoc session with the SMTP server
  * The ``connect()`` method now returns a context manager that yields an SMTP session
- **BACKWARDS INCOMPATIBLE** The ``OAuth2Authenticator`` class was refactored:

  * The return type of ``get_token()`` was changed to a (decoded) JSON web token –
    a dict containing the ``access_token`` and ``expires_in`` fields
  * The result of ``get_token()`` method is now automatically cached until the token's
    expiration time nears (configurable via the ``grace_period`` parameter in
    ``OAuth2Authenticator``)
  * Added the ``clear_cached_token()`` method
- Dropped support for Python 3.7
- Upgraded minimum AnyIO version to 4.2+
- The ``Bcc`` and ``Resent-Bcc`` are now properly added to the recipients list by the
  concrete client implementation
- The ``Bcc`` and ``Resent-Bcc`` headers are now automatically left out of the data in
  ``SMTPClientProtocol.data()`` to simplify client implementations

**1.2.1**

- Fixed ``LoginAuthenticator`` expecting the wrong questions (there should be a ``:`` at
  the end)
- Fixed compatibility with AnyIO 4

**1.2.0**

- Dropped support for Python 3.6
- Added support for Python 3.10
- Upgraded minimum AnyIO version to 3.0+
- Changed ``SMTPClientProtocol`` to only use ``SMTPUTF8`` if necessary (PR by
  Cole Maclean)

**1.1.0**

- Added missing ``authorization_id`` parameter to ``PlainAuthenticator`` (also fixes
  ``PLAIN`` authentication not working since this field was missing from the encoded
  output)
- Fixed sender/recipient addresses (in ``MAIL``/``RCPT`` commands) not being UTF-8
  encoded in the presence of the ``SMTPUTF8`` extension

**1.0.0**

- Initial release
