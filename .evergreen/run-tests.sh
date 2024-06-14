#!/usr/bin/bash
# Disable xtrace for security reasons (just in case it was accidentally set).
set +x
set -eu

# Fetch secrets
bash ${DRIVERS_TOOLS}/.evergreen/auth_aws/setup-secrets.sh
source ${DRIVERS_TOOLS}/.evergreen/auth_aws/secrets-export.sh

# Set up env
pushd ..
git clone https://github.com/mongodb/mongo-python-driver

set -x
"C:/python/Python38/python.exe" -m venv .venv
dos2unix -q .venv/Scripts/activate
. .venv/Scripts/activate
pip install "./mongo-python-driver[test]"
pip install -e ./src

pushd ./mongo-python-driver
.evergreen/run-mongodb-aws-test.sh regular
popd
popd
