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

from base64 import standard_b64encode
from collections import namedtuple

import requests

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

from pymongo_auth_aws.errors import PyMongoAuthAwsError


_AWS_REL_URI = 'http://169.254.170.2/'
_AWS_EC2_URI = 'http://169.254.169.254/'
_AWS_EC2_PATH = 'latest/meta-data/iam/security-credentials/'
_AWS_HTTP_TIMEOUT = 10


AwsCredential = namedtuple('AwsCredential', ['username', 'password', 'token'])
"""MONGODB-AWS credentials."""


def _aws_temp_credentials():
    """Construct temporary MONGODB-AWS credentials."""
    access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if access_key and secret_key:
        return AwsCredential(
            access_key, secret_key, os.environ.get('AWS_SESSION_TOKEN'))
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
        except (ValueError, requests.exceptions.RequestException):
            raise PyMongoAuthAwsError(
                'temporary MONGODB-AWS credentials could not be obtained')
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
            res = requests.post(_AWS_EC2_URI+'latest/api/token',
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
        except (ValueError, requests.exceptions.RequestException):
            raise PyMongoAuthAwsError(
                'temporary MONGODB-AWS credentials could not be obtained')

    try:
        temp_user = res_json['AccessKeyId']
        temp_password = res_json['SecretAccessKey']
        token = res_json['Token']
    except KeyError:
        # If temporary credentials cannot be obtained then drivers MUST
        # fail authentication and raise an error.
        raise PyMongoAuthAwsError(
            'temporary MONGODB-AWS credentials could not be obtained')

    return AwsCredential(temp_user, temp_password, token)


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
