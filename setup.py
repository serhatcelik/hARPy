import setuptools
from harpy import data

with open("README.md", "r") as readme:
    long_description = readme.read()

setuptools.setup(
    name="harpy-prjct",
    version=data.VERSION,
    author=data.AUTHOR,
    author_email=data.AUTHOR_EMAIL,
    url=data.PROJECT_URL,
    project_urls={
        "Source Code": data.PROJECT_URL,
    },
    description="Active/passive ARP discovery tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
    ],
    license="MIT",
    platforms=["Linux"],
    python_requires="~=3.4",
    keywords=["harpy", "arp", "discovery"],
    zip_safe=False,
    package_data={
        "": [
            "*.conf", "*.json",
        ],
    },
    options={
        "build_scripts": {
            "executable": "/bin/custom_python",
        },
    },
    entry_points={
        "console_scripts": [
            "harpy = harpy.__main__:setup_py_main",
        ],
    },
)
