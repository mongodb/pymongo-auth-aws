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

import sys

sys.path[0:0] = [""]

import pymongo_auth_aws

from pymongo_auth_aws.auth import _get_region
from pymongo_auth_aws.errors import PyMongoAuthAwsError

from test import unittest


class TestAuthAws(unittest.TestCase):

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


if __name__ == "__main__":
    unittest.main()
