Changelog
=========

Changes in Version 1.0.1
------------------------

- Fix a bug which caused authentication to fail when using non-default
  STS hosts with more than one dot (``.``). For example,
  "sts.us-west-2.amazonaws.com" is a valid STS host that would fail in
  version 1.0.0.

Changes in Version 1.0.0
------------------------

- Initial version.
- Implements `MONGODB-AWS authentication`_ support for PyMongo.

.. _MONGODB-AWS authentication:
   https://github.com/mongodb/specifications/blob/8f16c36/source/auth/auth.rst#mongodb-aws
