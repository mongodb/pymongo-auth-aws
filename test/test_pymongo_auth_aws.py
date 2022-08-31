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

"""Test the pymongo-auth-aws module."""

from datetime import datetime, timedelta
import os
import sys
import tempfile

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

sys.path[0:0] = [""]

import botocore.session
from botocore.stub import Stubber
import requests_mock

import bson
from bson.binary import Binary
import pymongo_auth_aws

from pymongo_auth_aws import auth
from pymongo_auth_aws.auth import _get_region, aws_temp_credentials, AwsSaslContext, AwsCredential
from pymongo_auth_aws.errors import PyMongoAuthAwsError

from test import unittest

os.environ['AWS_SHARED_CREDENTIALS_FILE'] = '/tmp'
AWS_DATE_FORMAT = r"%Y-%m-%dT%H:%M:%SZ"

class TestAuthAws(unittest.TestCase):

    def setUp(self):
        auth.set_cached_credentials(None)
        os.environ.pop('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', None)
        return unittest.TestCase.setUp(self)

    def assertVersionLike(self, version):
        self.assertTrue(isinstance(version, str), msg=version)
        # There should be at least one dot: "1.0" or "1.0.0" not "1".
        self.assertGreaterEqual(len(version.split('.')), 2, msg=version)

    def test_version(self):
        self.assertVersionLike(pymongo_auth_aws.__version__)

    def test_region(self):
        # Default region is us-east-1.
        self.assertEqual('us-east-1', _get_region('sts.amazonaws.com'))
        self.assertEqual('us-east-1', _get_region('first'))
        self.assertEqual('us-east-1', _get_region('f'))
        # Otherwise, the region is the second label.
        self.assertEqual('second', _get_region('first.second'))
        self.assertEqual('second', _get_region('first.second.third'))
        self.assertEqual('second', _get_region('sts.second.amazonaws.com'))
        # Assert invalid hosts cause an error.
        self.assertRaises(PyMongoAuthAwsError, _get_region, '')
        self.assertRaises(PyMongoAuthAwsError, _get_region, 'i'*256)
        self.assertRaises(PyMongoAuthAwsError, _get_region, 'first..second')
        self.assertRaises(PyMongoAuthAwsError, _get_region, '.first.second')
        self.assertRaises(PyMongoAuthAwsError, _get_region, 'first.second.')

    def ensure_equal(self, creds, expected):
        self.assertEqual(creds.username, expected['AccessKeyId'])
        self.assertEqual(creds.password, expected['SecretAccessKey'])
        if 'SessionToken' in expected:
            self.assertEqual(creds.token, expected['SessionToken'])
        else:
            self.assertEqual(creds.token, expected['Token'])

    def test_aws_temp_credentials_env_variables(self):
        os.environ['AWS_ACCESS_KEY_ID'] = 'foo'
        os.environ['AWS_SECRET_ACCESS_KEY'] = 'bar'
        creds = aws_temp_credentials()
        del os.environ['AWS_ACCESS_KEY_ID']
        del os.environ['AWS_SECRET_ACCESS_KEY']
        self.assertEqual(creds.username, 'foo')
        self.assertEqual(creds.password, 'bar')
        self.assertEqual(creds.token, None)

    def test_aws_temp_credentials(self):
        os.environ['AWS_CONTAINER_CREDENTIALS_FULL_URI'] = uri = 'https://localhost'
        expected = dict(AccessKeyId='foo', SecretAccessKey='bar', Token='fizz', Expiration='2016-03-15T00:05:07Z')
        with requests_mock.Mocker() as m:
            m.get(uri, json=expected)
            creds = aws_temp_credentials()
        self.ensure_equal(creds, expected)

    def test_cache_credentials(self):
        auth.set_use_cached_credentials(True)
        os.environ['AWS_CONTAINER_CREDENTIALS_FULL_URI'] = uri = 'https://localhost'
        tomorrow = datetime.now(auth.utc) + timedelta(days=1)
        expected = dict(AccessKeyId='foo', SecretAccessKey='bar', Token='fizz', Expiration=tomorrow.strftime(AWS_DATE_FORMAT))
        with requests_mock.Mocker() as m:
            m.get(uri, json=expected)
            creds = aws_temp_credentials()
        self.ensure_equal(creds, expected)

        creds = aws_temp_credentials()
        self.ensure_equal(creds, expected)

    def test_caching_disabled(self):
        auth.set_use_cached_credentials(False)
        os.environ['AWS_CONTAINER_CREDENTIALS_FULL_URI'] = uri = 'https://localhost'
        soon = datetime.now(auth.utc) + timedelta(minutes=10)
        expected = dict(AccessKeyId='foo', SecretAccessKey='bar', Token='fizz', Expiration=soon.strftime(AWS_DATE_FORMAT))
        with requests_mock.Mocker() as m:
            m.get(uri, json=expected)
            creds = aws_temp_credentials()
        self.ensure_equal(creds, expected)

        tomorrow = datetime.now(auth.utc) + timedelta(days=1)
        expected['Expiration'] = tomorrow.strftime(AWS_DATE_FORMAT)
        with requests_mock.Mocker() as m:
            m.get('%sfoo' % auth._AWS_REL_URI, json=expected)
            creds = aws_temp_credentials()
        self.ensure_equal(creds, expected)

    def test_cache_expired(self):
        auth.set_use_cached_credentials(True)
        os.environ['AWS_CONTAINER_CREDENTIALS_FULL_URI'] = uri = 'https://localhost'
        expired = datetime.now(auth.utc) - timedelta(hours=1)
        expected = dict(AccessKeyId='foo', SecretAccessKey='bar', Token='fizz', Expiration=expired.strftime(AWS_DATE_FORMAT))
        with requests_mock.Mocker() as m:
            m.get(uri, json=expected)
            creds = aws_temp_credentials()

        self.ensure_equal(creds, expected)

        expected['AccessKeyId'] = 'fizz'
        with requests_mock.Mocker() as m:
            m.get(uri, json=expected)
            creds = aws_temp_credentials()

        self.ensure_equal(creds, expected)

    def test_cache_expires_soon(self):
        auth.set_use_cached_credentials(True)
        os.environ['AWS_CONTAINER_CREDENTIALS_FULL_URI'] = uri = 'https://localhost'
        soon = datetime.now(auth.utc) + timedelta(seconds=30)
        expected = dict(AccessKeyId='foo', SecretAccessKey='bar', Token='fizz', Expiration=soon.strftime(AWS_DATE_FORMAT))
        with requests_mock.Mocker() as m:
            m.get(uri, json=expected)
            creds = aws_temp_credentials()

        self.ensure_equal(creds, expected)

        expected['AccessKeyId'] = 'fizz'
        with requests_mock.Mocker() as m:
            m.get(uri, json=expected)
            creds = aws_temp_credentials()

        self.ensure_equal(creds, expected)


class _AwsSaslContext(AwsSaslContext):

    def binary_type(self):
        """Return the bson.binary.Binary type."""
        return Binary

    def bson_encode(self, doc):
        """Encode a dictionary to BSON."""
        return bson.encode(doc)

    def bson_decode(self, data):
        """Decode BSON to a dictionary."""
        return bson.decode(data)



class TestAwsSaslContext(unittest.TestCase):

    def test_step(self):
        creds = AwsCredential('foo', 'bar', 'baz')
        test = _AwsSaslContext(creds)
        response = bson.decode(test.step(None))
        nonce = response['r'] + os.urandom(32)
        # Python 2.7 support.
        if sys.version_info[0] == 2:
            nonce = Binary(nonce)
        payload = bson.encode(dict(s=nonce, h='foo.com'))
        response = test.step(payload)
        self.assertIsInstance(response, Binary)


if __name__ == "__main__":
    unittest.main()
