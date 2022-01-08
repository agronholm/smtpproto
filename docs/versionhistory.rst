Version history
===============

This library adheres to `Semantic Versioning 2.0 <http://semver.org/>`_.

**UNRELEASED**

- Dropped support for Python 3.6
- Added support for Python 3.10
- Fixed ``SyncClient`` leaving a blocking portal open if the initial connection fails

**1.1.0**

- Added missing ``authorization_id`` parameter to ``PlainAuthenticator`` (also fixes ``PLAIN``
  authentication not working since this field was missing from the encoded output)
- Fixed sender/recipient addresses (in ``MAIL``/``RCPT`` commands) not being UTF-8 encoded in the
  presence of the ``SMTPUTF8`` extension

**1.0.0**

- Initial release
