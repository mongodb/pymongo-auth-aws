# Copyright 2020-present MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""MONGODB-AWS authentication support for PyMongo."""

import os
from functools import wraps

from base64 import standard_b64encode
from collections import namedtuple
from datetime import tzinfo, timedelta, datetime


import boto3
import requests

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.utils import parse_to_aware_datetime

from pymongo_auth_aws.errors import PyMongoAuthAwsError


_AWS_REL_URI = 'http://169.254.170.2/'
_AWS_EC2_URI = 'http://169.254.169.254/'
_AWS_EC2_PATH = 'latest/meta-data/iam/security-credentials/'
_AWS_HTTP_TIMEOUT = 10

"""MONGODB-AWS credentials."""
class AwsCredential:
    def __init__(self, username, password, token, expiration=None):
        self.username = username
        self.password = password
        self.token = token
        self.expiration = expiration


_credential_buffer_seconds = 60 * 5

__cached_credentials = None

def _get_cached_credentials():
    """Central point for accessing cached credentials."""
    return __cached_credentials

def _set_cached_credentials(credentials):
    """Central point for setting cached credentials."""
    global __cached_credentials
    __cached_credentials = credentials


ZERO = timedelta(0)

# A Python 2.7-compliant UTC class (from stdlib docs).
# When we drop Python 2.7 support we can use `timezone.utc` instead.

class _UTC(tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO

utc = _UTC()


def _aws_temp_credentials():
    """Construct temporary MONGODB-AWS credentials."""
    # Store the variable locally for safe threaded access.
    creds = _get_cached_credentials()

    access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if access_key and secret_key:
        return AwsCredential(
            access_key, secret_key, os.environ.get('AWS_SESSION_TOKEN'))

    # Check to see if we have valid credentials.
    if creds and creds.expiration is not None:
        now_utc = datetime.now(utc)
        exp_utc = parse_to_aware_datetime(creds.expiration)
        if (exp_utc - now_utc).total_seconds() >= _credential_buffer_seconds:
            return creds

    # Check if environment variables exposed by IAM Roles for Service Accounts (IRSA) are present.
    # See https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html for details.
    irsa_web_id_file = os.getenv('AWS_WEB_IDENTITY_TOKEN_FILE')
    irsa_role_arn = os.getenv('AWS_ROLE_ARN')
    if irsa_web_id_file and irsa_role_arn:
        try:
            with open(irsa_web_id_file) as f:
                irsa_web_id_token = f.read()
            role_session_name = os.getenv('AWS_ROLE_SESSION_NAME', 'pymongo-auth-aws')
            creds = _irsa_assume_role(irsa_role_arn, irsa_web_id_token, role_session_name)
            _set_cached_credentials(creds)
            return creds
        except Exception as exc:
            raise PyMongoAuthAwsError(
                'temporary MONGODB-AWS credentials could not be obtained, '
                'error: %s' % (exc,))

    # If the environment variable
    # AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is set then drivers MUST
    # assume that it was set by an AWS ECS agent and use the URI
    # http://169.254.170.2/$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI to
    # obtain temporary credentials.
    relative_uri = os.environ.get('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI')
    if relative_uri is not None:
        try:
            res = requests.get(_AWS_REL_URI+relative_uri,
                               timeout=_AWS_HTTP_TIMEOUT)
            res_json = res.json()
        except (ValueError, requests.exceptions.RequestException) as exc:
            raise PyMongoAuthAwsError(
                'temporary MONGODB-AWS credentials could not be obtained, '
                'error: %s' % (exc,))
    else:
        # If the environment variable AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is
        # not set drivers MUST assume we are on an EC2 instance and use the
        # endpoint
        # http://169.254.169.254/latest/meta-data/iam/security-credentials
        # /<role-name>
        # whereas role-name can be obtained from querying the URI
        # http://169.254.169.254/latest/meta-data/iam/security-credentials/.
        try:
            # Get token
            headers = {'X-aws-ec2-metadata-token-ttl-seconds': "30"}
            res = requests.put(_AWS_EC2_URI+'latest/api/token',
                               headers=headers, timeout=_AWS_HTTP_TIMEOUT)
            token = res.content
            # Get role name
            headers = {'X-aws-ec2-metadata-token': token}
            res = requests.get(_AWS_EC2_URI+_AWS_EC2_PATH, headers=headers,
                               timeout=_AWS_HTTP_TIMEOUT)
            role = res.text
            # Get temp creds
            res = requests.get(_AWS_EC2_URI+_AWS_EC2_PATH+role,
                               headers=headers, timeout=_AWS_HTTP_TIMEOUT)
            res_json = res.json()
        except (ValueError, requests.exceptions.RequestException) as exc:
            raise PyMongoAuthAwsError(
                'temporary MONGODB-AWS credentials could not be obtained, '
                'error: %s' % (exc,))

    # See https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html#examples for expected result format.
    try:
        temp_user = res_json['AccessKeyId']
        temp_password = res_json['SecretAccessKey']
        session_token = res_json['Token']
        expiration = res_json['Expiration']
    except KeyError:
        # If temporary credentials cannot be obtained then drivers MUST
        # fail authentication and raise an error.
        raise PyMongoAuthAwsError(
            'temporary MONGODB-AWS credentials could not be obtained')

    creds = AwsCredential(temp_user, temp_password, session_token, expiration)
    _set_cached_credentials(creds)
    raise ValueError(f'creds expire: {expiration}')
    return creds


def _irsa_assume_role(role_arn, token, role_session_name):
    """Call sts:AssumeRoleWithWebIdentity and return temporary credentials."""
    sts_client = boto3.client('sts')
    # See https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html.
    resp = sts_client.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=role_session_name,
        WebIdentityToken=token
    )
    creds = resp['Credentials']
    access_key = creds['AccessKeyId']
    secret_key = creds['SecretAccessKey']
    session_token = creds['SessionToken']
    expiration = creds['Expiration']

    return AwsCredential(access_key, secret_key, session_token, expiration)


_AWS4_HMAC_SHA256 = 'AWS4-HMAC-SHA256'
_AWS_SERVICE = 'sts'


def _get_region(sts_host):
    """Return the AWS region to use for the given host."""
    # Drivers must also validate that the host is greater than 0 and
    # less than or equal to 255 bytes per RFC 1035.
    if not sts_host or len(sts_host) > 255:
        raise PyMongoAuthAwsError(
            "Server returned an invalid sts host: %s" % (sts_host,))

    parts = sts_host.split('.')
    if len(parts) == 1 or sts_host == 'sts.amazonaws.com':
        return 'us-east-1'  # Default

    # Check for empty labels (eg "invalid..host" or ".invalid.host").
    if not all(parts):
        raise PyMongoAuthAwsError(
            "Server returned an invalid sts host: %s" % (sts_host,))

    return parts[1]


def _aws_auth_header(credentials, server_nonce, sts_host):
    """Signature Version 4 Signing Process to construct the authorization header
    """
    region = _get_region(sts_host)

    request_parameters = 'Action=GetCallerIdentity&Version=2011-06-15'
    encoded_nonce = standard_b64encode(server_nonce).decode('utf8')
    request_headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': str(len(request_parameters)),
        'Host': sts_host,
        'X-MongoDB-Server-Nonce': encoded_nonce,
        'X-MongoDB-GS2-CB-Flag': 'n',
    }
    request = AWSRequest(method="POST", url="/", data=request_parameters,
                         headers=request_headers)
    boto_creds = Credentials(credentials.username, credentials.password,
                             token=credentials.token)
    auth = SigV4Auth(boto_creds, "sts", region)
    auth.add_auth(request)
    final = {
        'a': request.headers['Authorization'],
        'd': request.headers['X-Amz-Date']
    }
    if credentials.token:
        final['t'] = credentials.token
    return final


def _handle_credentials(func):
    @wraps(func)
    def inner(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception:
            _set_cached_credentials(None)
            raise
    return inner


class AwsSaslContext(object):
    """MONGODB-AWS authentication support.

    :Parameters:
      - `credentials`: The :class:`AwsCredential` to use for authentication.
    """
    def __init__(self, credentials):
        self._credentials = credentials
        self._step = 0
        self._client_nonce = None

    def step(self, server_payload):
        """Step through the SASL conversation.

        :Parameters:
          - `server_payload`: The server payload (SASL challenge). Must be a
            bytes-like object.

        :Returns:
          The response payload for the next SASL step.

        :Raises:
          :class:`~pymongo_auth_aws.PyMongoAuthAwsError` on error.
        """
        self._step += 1
        if self._step == 1:
            return self._first_payload()
        elif self._step == 2:
            return self._second_payload(server_payload)
        else:
            raise PyMongoAuthAwsError('MONGODB-AWS failed: too many steps')
        pass

    @_handle_credentials
    def _first_payload(self):
        """Return the first SASL payload."""
        # If a username and password are not provided, drivers MUST query
        # a link-local AWS address for temporary credentials.
        if self._credentials.username is None:
            self._credentials = _aws_temp_credentials()

        # Client first.
        client_nonce = os.urandom(32)
        self._client_nonce = client_nonce
        payload = {'r': self.binary_type()(client_nonce), 'p': 110}
        return self.binary_type()(self.bson_encode(payload))

    @_handle_credentials
    def _second_payload(self, server_payload):
        """Return the second and final SASL payload."""
        if not server_payload:
            raise PyMongoAuthAwsError(
                'MONGODB-AWS failed: server payload empty')

        server_payload = self.bson_decode(server_payload)
        server_nonce = server_payload['s']
        if len(server_nonce) != 64 or not server_nonce.startswith(
                self._client_nonce):
            raise PyMongoAuthAwsError("Server returned an invalid nonce.")

        sts_host = server_payload['h']
        payload = _aws_auth_header(self._credentials, server_nonce, sts_host)
        return self.binary_type()(self.bson_encode(payload))

    # Dependency injection:
    def binary_type(self):
        """Return the bson.binary.Binary type."""
        raise NotImplementedError

    def bson_encode(self, doc):
        """Encode a dictionary to BSON."""
        raise NotImplementedError

    def bson_decode(self, data):
        """Decode BSON to a dictionary."""
        raise NotImplementedError
