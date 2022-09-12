Changelog
=========

Changes in Version 1.1.0
------------------------

- Use ``boto3`` to fetch on-demand credentials, expanding and standardizing
  authorization capabilities.  This includes EKS IAM credentials that use
  ``AssumeRoleWithWebIdentity``.
- Enable opt-in caching of fetched on-demand credentials, to prevent rate
  limiting.
- Make the ``pymongo_auth_aws.auth.aws_temp_credentials`` function public
  so it can be used in ``pymongocrypt``.


Changes in Version 1.0.2
------------------------

- Fix a bug which caused MONGODB-AWS authentication to fail in some
  EC2 Instance configurations. Previous versions incorrectly used a POST
  request when creating the session token for Instance Metadata Service
  Version 2 (IMDSv2).

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
