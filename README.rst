.. image:: https://github.com/agronholm/smtpproto/actions/workflows/test.yml/badge.svg
  :target: https://github.com/agronholm/smtpproto/actions/workflows/test.yml
  :alt: Build Status
.. image:: https://coveralls.io/repos/github/agronholm/smtpproto/badge.svg?branch=master
  :target: https://coveralls.io/github/agronholm/smtpproto?branch=master
  :alt: Code Coverage
.. image:: https://readthedocs.org/projects/smtpproto/badge/
  :target: https://smtpproto.readthedocs.org/
  :alt: Documentation

This library contains a (client-side) sans-io_ implementation of the ESMTP_ protocol.
A concrete, asynchronous I/O implementation is also provided, via the AnyIO_ library.

The following SMTP extensions are supported:

* 8BITMIME_
* AUTH_
* SIZE_ (max message size reporting only)
* SMTPUTF8_
* STARTTLS_

You can find the documentation `here <https://smtpproto.readthedocs.org/>`_.

.. _sans-io: https://sans-io.readthedocs.io/
.. _ESMTP: https://tools.ietf.org/html/rfc5321
.. _AnyIO: https://pypi.org/project/anyio/
.. _8BITMIME: https://tools.ietf.org/html/rfc1652
.. _AUTH: https://tools.ietf.org/html/rfc4954
.. _SMTPUTF8: https://tools.ietf.org/html/rfc6531
.. _SIZE: https://tools.ietf.org/html/rfc1870
.. _STARTTLS: https://tools.ietf.org/html/rfc3207
