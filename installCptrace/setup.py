#!/usr/bin/env python

# Prepare a release:
#
#  - git pull --rebase  # check that there is no incoming changesets
#  - check version in ptrace/version.py and doc/conf.py
#  - set release date in doc/changelog.rst
#  - check that "python3 setup.py sdist" contains all files tracked by
#    the SCM (Git): update MANIFEST.in if needed
#  - git commit -a -m "prepare release VERSION"
#  - Remove untracked files/dirs: git clean -fdx
#  - run tests, type: tox
#  - git push
#  - check Travis status:
#    https://travis-ci.org/vstinner/python-ptrace
#
# Release a new version:
#
#  - git tag VERSION
#  - git push --tags
#  - Remove untracked files/dirs: git clean -fdx
#  - python3 setup.py sdist bdist_wheel
#  - twine upload dist/*
#
# After the release:
#
#  - increment version in  ptrace/version.py and doc/conf.py
#  - git commit -a -m "post-release"
#  - git push

from __future__ import with_statement

from imp import load_source
from os import path
try:
    # setuptools supports bdist_wheel
    from setuptools import setup
except ImportError:
    from distutils.core import setup


MODULES = ["ptrace", "ptrace.binding", "ptrace.syscall", "ptrace.debugger"]

SCRIPTS = ("strace.py", "gdb.py")

CLASSIFIERS = [
    'Intended Audience :: Developers',
    'Development Status :: 7 - Inactive',
    'Environment :: Console',
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Operating System :: OS Independent',
    'Natural Language :: English',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
]

with open('README.rst') as fp:
    LONG_DESCRIPTION = fp.read()

ptrace = load_source("version", path.join("ptrace", "version.py"))
PACKAGES = {}
for name in MODULES:
    PACKAGES[name] = name.replace(".", "/")

install_options = {
    "name": ptrace.PACKAGE,
    "version": ptrace.VERSION,
    "url": ptrace.WEBSITE,
    "download_url": ptrace.WEBSITE,
    "author": "Victor Stinner",
    "description": "python binding of ptrace",
    "long_description": LONG_DESCRIPTION,
    "classifiers": CLASSIFIERS,
    "license": ptrace.LICENSE,
    "packages": list(PACKAGES.keys()),
    "package_dir": PACKAGES,
    "scripts": SCRIPTS,
    "install_requires": ["six"],
}

setup(**install_options)
