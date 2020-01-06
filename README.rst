.. image:: https://dev.azure.com/alexgronholm/smtpproto/_apis/build/status/agronholm.smtpproto?branchName=master
  :alt: Build Status
.. image:: https://img.shields.io/azure-devops/coverage/agronholm/smtpproto/1/master.svg
  :alt: Code Coverage
.. image:: https://readthedocs.org/projects/smtpproto/badge/?version=latest
  :target: https://smtpproto.readthedocs.io/en/latest/?badge=latest
  :alt: Documentation

This library contains a sans-io_ implementation of the (client-side) ESMTP_ protocol.
A concrete, asynchronous I/O implementation is also provided, via the AnyIO_ library.

The following SMTP extensions are supported:

* 8BITMIME_
* AUTH_
* SIZE_ (max message size reporting only)
* SMTPUTF8_
* STARTTLS_

.. _sans-io: https://sans-io.readthedocs.io/
.. _ESMTP: https://tools.ietf.org/html/rfc5321
.. _AnyIO: https://pypi.org/project/anyio/
.. _8BITMIME: https://tools.ietf.org/html/rfc1652
.. _AUTH: https://tools.ietf.org/html/rfc4954
.. _SMTPUTF8: https://tools.ietf.org/html/rfc6531
.. _SIZE: https://tools.ietf.org/html/rfc1870
.. _STARTTLS: https://tools.ietf.org/html/rfc3207
