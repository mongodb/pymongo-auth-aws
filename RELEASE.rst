=========================
pymongo-auth-aws Releases
=========================

Versioning
----------

pymongo-auth-aws's version numbers follow `semantic versioning`_: each version
number is structured "major.minor.patch". Patch releases fix bugs, minor
releases add features (and may fix bugs), and major releases include API
changes that break backwards compatibility (and may add features and fix
bugs).

In between releases we add .devN to the version number to denote the version
under development. So if we just released 1.0.0, then the current dev
version might be 1.0.1.dev0 or 1.1.0.dev0.

.. _semantic versioning: http://semver.org/

Release Process
---------------

pymongo-auth-aws ships universal Python wheels.

#. Add a changelog entry for this release in CHANGELOG.rst.
#. Bump "__version__" in pymongo-auth-aws/version.py. Commit the change and tag
   the release. Immediately bump the "__version__" to "dev0" in a new commit::

     $ # Bump to release version number
     $ git commit -a -m "pymongo-auth-aws <release version number>"
     $ git tag -a <release version number> -m "pymongo-auth-aws <release version number>"
     $ # Bump to dev version number
     $ git commit -a -m "BUMP pymongo-auth-aws <release version number>"
     $ git push
     $ git push --tags

#. Build the release packages::

     $ git clone git@github.com:mongodb/pymongo-auth-aws.git
     $ cd pymongo-auth-aws/
     $ git checkout "pymongo-auth-aws <release version number>"
     $ python3 setup.py sdist
     $ python3 setup.py bdist_wheel

   This will create the following distributions::

     $ ls dist
     pymongo-auth-aws-<version>.tar.gz
     pymongo-auth-aws-<version>-py2.py3-none-any.whl

#. Upload all the release packages to PyPI with twine::

     $ python3 -m twine upload dist/*
