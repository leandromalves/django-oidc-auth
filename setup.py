# -*- coding: utf-8 -*-
import os
from setuptools import setup, find_packages


def install_requires():
    requirements = read_file('requirements.txt')
    return requirements


def read_file(filename):
    """Read a file into a string"""
    path = os.path.abspath(os.path.dirname(__file__))
    filepath = os.path.join(path, filename)
    try:
        return open(filepath).read()
    except IOError:
        return ''

setup(
    name='django-oidc-auth',
    version='0.1.1',
    url='https://github.com/intelie/django-oidc-auth',
    author='Lucas S. Magalhães',
    author_email='lucas.sampaio@intelie.com.br',
    description='OpenID Connect client for Django applications',
    long_description='WIP',
    include_package_data=True,
    packages=find_packages(exclude=['*.tests']),
    install_requires=install_requires(),
    classifiers=[
        'Framework :: Django',
    ],
)
