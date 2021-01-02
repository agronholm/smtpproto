Version history
===============

This library adheres to `Semantic Versioning 2.0 <http://semver.org/>`_.

**1.1.0**

- Added missing ``authorization_id`` parameter to ``PlainAuthenticator`` (also fixes ``PLAIN``
  authentication not working since this field was missing from the encoded output)
- Fixed sender/recipient addresses (in ``MAIL``/``RCPT`` commands) not being UTF-8 encoded in the
  presence of the ``SMTPUTF8`` extension

**1.0.0**

- Initial release
