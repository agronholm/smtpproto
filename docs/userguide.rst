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


Sending mail via Office 365
---------------------------

.. warning:: It is currently not clear what actual permissions the service account
    requires. As such, this example *should* work but has never been successfully
    tested.

The following example assumes the presence of a registered `Entra ID application`_
authorized to send email via SMTP (using the ``SMTP.Send`` scope). It uses the
`device code flow`_ to obtain an access token.

In order for the device code flow to work for the registered application, the following
settings must be in place:

* The redirect URI for the application must be
  ``https://login.microsoftonline.com/common/oauth2/nativeclient``
* The ``Treat application as a public client`` option must be enabled
* The ``SMTP.Send`` permission from ``Microsoft Graph`` must be added in the configured
  permissions

In addition, your Entra ID must not have `Security defaults`_ enabled.

.. literalinclude:: ../examples/office365.py
   :language: python

.. _Entra ID application: https://docs.microsoft.com/en-us/exchange/client-developer/\
    legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth\
    #register-your-application
.. _device code flow: https://docs.microsoft.com/en-us/azure/active-directory/develop/\
    v2-oauth2-device-code
.. _Security defaults: https://docs.microsoft.com/fi-fi/azure/active-directory/\
    fundamentals/concept-fundamentals-security-defaults
