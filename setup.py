import setuptools

with open("README.md", "r") as fh:
    LONG_DESCRIPTION = fh.read()

setuptools.setup(
    name="vmsshgen",
    version="1.0.0",
    author="Dmitry Romanenko",
    author_email="Dmitry@Romanenko.in",
    description="Automatic generation of SSH keys for VM",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/dimon222/py-vmsshgen",
    packages=setuptools.find_packages(),
    license="Apache License 2.0",
    install_requires=["asyncssh"],
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Security :: Cryptography",
        "Environment :: Console",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    entry_points={"console_scripts": ["vmsshgen = vmsshgen:main"]},
)
