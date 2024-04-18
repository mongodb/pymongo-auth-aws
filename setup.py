from setuptools import setup


def parse_reqs_file(fname):
    with open(fname) as fid:  # noqa:PTH123
        lines = [li.strip() for li in fid.readlines()]
    return [li for li in lines if li and not li.startswith("#")]


extras_require = dict(test=parse_reqs_file("requirements-test.txt"))

setup(install_requires=parse_reqs_file("requirements.txt"), extras_require=extras_require)
