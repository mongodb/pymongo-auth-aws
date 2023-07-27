import os

from setuptools import setup, find_packages

with open('README.rst', 'rb') as f:
    LONG_DESCRIPTION = f.read().decode('utf8')

# Single source the version.
version_file = os.path.realpath(os.path.join(
    os.path.dirname(__file__), 'pymongo_auth_aws', 'version.py'))
version = {}
with open(version_file) as fp:
    exec(fp.read(), version)

setup(
    name="pymongo-auth-aws",
    version=version['__version__'],
    description="MONGODB-AWS authentication support for PyMongo",
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/x-rst',
    packages=find_packages(exclude=['test']),
    install_requires=['boto3', 'botocore'],
    extras_require={
        "test": ["pymongo", "pytest"]
    },
    author="Shane Harvey",
    author_email="drivers-python-noreply@mongodb.com",
    url="https://github.com/mongodb/pymongo-auth-aws",
    keywords=["mongo", "mongodb", "pymongo-auth-aws", "pymongo", "MONGODB-AWS"],
    license="Apache License, Version 2.0",
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Database"]
)
