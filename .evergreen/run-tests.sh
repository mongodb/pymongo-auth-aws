#!/usr/bin/bash
# Disable xtrace for security reasons (just in case it was accidentally set).
set +x
set -eu

# Set up env
pushd ..
git clone https://github.com/mongodb/mongo-python-driver

set -x
/opt/python/3.10/bin/python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install "./mongo-python-driver[test]"
pip install -e ./src

pushd ./mongo-python-driver
bash ./.evergreen/just.sh run-server auth_aws
bash ./.evergreen/just.sh setup-tests auth_aws regular
source ./.evergreen/scripts/test-env.sh
python -m pytest -v -m auth_aws

popd
popd
