Version history
===============

This library adheres to `Semantic Versioning 2.0 <http://semver.org/>`_.

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
