# -*- coding: utf-8 -*-
from setuptools import find_packages, setup

with open('requirements.txt') as f:
    required = f.read().splitlines()

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name='reai-ida',
    version='0.1',
    packages=find_packages(),
    install_requires=required,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/RevEngAI/reai-ida",
)
