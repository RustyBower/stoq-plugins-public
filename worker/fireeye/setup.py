from setuptools import setup, find_packages

setup(
    name="fireeye",
    version="0.1.5",
    author="Marcus LaFerrera (@mlaferrera), Aaron Gee-Clough (@gclef_) & Adam Trask (@taskr)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Submit a file to a Fireeye MAS/AX via filesystem or API",
    packages=find_packages(),
    include_package_data=True,
)
