from setuptools import setup, find_packages
import os

init_py = os.path.join(os.path.dirname(__file__), "file_security_defender", "__init__.py")
version = {}
with open(init_py) as f:
    exec(f.read(), version)
project_version = version["__version__"]

setup(
    name="File-Security-Defender",
    author="Yusuke Toyama (koko1928)",
    author_email="Ym5saGJtTmhkQT09@protonmail.com",
    maintainer="Yusuke Toyama (koko1928)",
    maintainer_email="Ym5saGJtTmhkQT09@protonmail.com",
    description="This application improves security by encrypting and signing files to keep them private.",
    long_description=open('README.md').read(),
    license="MIT License",
    url="https://github.com/koko1928/File-Security-Defender",
    version=project_version,
    python_requires=">=3.6",
    install_requires=[
        "cryptography",
        "tkinter",
    ],
    extras_require=extras,
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: Software Development",
        "Topic :: Utilities",
    ],
)
