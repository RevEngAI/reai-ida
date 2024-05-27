#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from os import walk
from os.path import join
from setuptools import find_packages, setup

from __ida_setup__ import IdaPluginInstallCommand
from revengai import __version__


with open("requirements.txt") as fd:
    required = fd.read().splitlines()

with open("README.md", encoding="utf-8") as fd:
    long_description = fd.read()


extra_files = []
for (path, _, filenames,) in walk("./revengai"):
    for filename in filenames:
        extra_files.append(join(path, filename))


setup(
    name="reai-ida",
    version=__version__,
    python_requires=">=3.9",
    author="Yannick Tournier",
    author_email="yannick@reveng.ai",
    packages=find_packages(),
    install_requires=required,
    include_package_data=True,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/RevEngAI/reai-ida",
    py_modules=["reveng",],
    package_data={
        "ida_plugins": extra_files,
    },
    classifiers=[
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
    ],
    cmdclass={
        "install": IdaPluginInstallCommand,
    },
)
