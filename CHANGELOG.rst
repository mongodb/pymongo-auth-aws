Changelog
=========

Changes in Version 1.2.0
------------------------

- Support Python versions 3.8-3.12, to align with PyMongo 4 supported versions.
  Drop support for Python 2.7, 3.4, 3.5, 3.6, and 3.7.
- Add Secure Software Development Life Cycle automation to release process.
  GitHub Releases now include a Software Bill of Materials, and signature
  files corresponding to the distribution files released on PyPI.

Changes in Version 1.1.0
------------------------

- Use ``boto3`` to handle ``credentials``, expanding and standardizing
  authorization capabilities.  This includes EKS IAM credentials that use
  ``AssumeRoleWithWebIdentity``.
- Enable opt-in caching of fetched on-demand credentials, to prevent rate
  limiting.
- Make the ``pymongo_auth_aws.auth.aws_temp_credentials`` function public
  so it can be used in ``pymongocrypt``.


Notes
.....
Because we are now using ``boto3`` to handle credentials, the order and
locations of credentials are slightly different from before.  Particularly,
if you have a shared AWS credentials or config file,
then those credentials will be used by default if AWS auth environment
variables are not set.  To override this behavior, set
``AWS_SHARED_CREDENTIALS_FILE=""`` in your shell or add
``os.environ["AWS_SHARED_CREDENTIALS_FILE"] = ""`` to your script or
application.  Alternatively, you can create an AWS profile specifically for
your MongoDB credentials and set ``AWS_PROFILE`` to that profile name.

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

.. _credentials:
   https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html

.. _MONGODB-AWS authentication:
   https://github.com/mongodb/specifications/blob/8f16c36/source/auth/auth.rst#mongodb-aws
