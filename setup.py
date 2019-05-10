from setuptools import setup, find_packages


setup(
    name="samilter",
    version="1.0.0",
    extras_require={
        "develop": ["pytest", "pylint-runner"]
    },
    install_requires=[
        "pymilter", "dkimpy", "pyspf", "py3dns", "authres", "dkimpy_milter"
    ],
    entry_points={
        "console_scripts": [
            "samilter = samilter.samilter:main",
        ],
    },
    packages=find_packages(exclude=('tests', 'docs')),
)