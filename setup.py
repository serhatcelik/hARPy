# This file is part of hARPy
# Released under the MIT license
# Copyright (c) Serhat Çelik

"""Setup script."""

import setuptools
from harpy.__version__ import __version__
from harpy.__author__ import __author__, __email__, __gitlink__

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='harpy-prjct',
    version=__version__,
    author=__author__,
    author_email=__email__,
    url=__gitlink__,
    description='Harpy who is using ARP',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=setuptools.find_packages(),
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3 :: Only'
    ],
    python_requires='>=3.6',
    package_data={
        '': [
            '*.json'
        ]
    },
    entry_points={
        'console_scripts': [
            'harpy = harpy.__main__:main'
        ]
    },
    options={
        'build_scripts': {
            'executable': '/bin/custom_python'
        }
    }
)
