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

* httpx_
* PyJWT_ (Gmail only)

.. _httpx: https://pypi.org/project/httpx/
.. _PyJWT: https://pypi.org/project/pyjwt/


Sending mail via a local SMTP server
------------------------------------

.. literalinclude:: ../examples/local.py
   :language: python


Sending mail via Gmail
----------------------

The `developer documentation`_ for the G Suite describes how to use the XOAUTH2
mechanism for authenticating against the Gmail SMTP server. The following is a practical
example of how to extend the :class:`~.auth.OAuth2Authenticator` class to obtain an
access token and use it to send an email via Gmail.

The following example assumes the presence of an existing `G Suite service account`_
authorized to send email via SMTP (using the ``https://mail.google.com/`` scope).

.. literalinclude:: ../examples/gmail.py
   :language: python

.. _developer documentation: https://developers.google.com/gmail/imap/xoauth2-protocol
.. _G Suite service account: https://support.google.com/a/answer/7378726?hl=en
