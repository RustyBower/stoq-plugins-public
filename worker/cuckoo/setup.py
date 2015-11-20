from setuptools import setup, find_packages

setup(
    name="cuckoo",
    version="0.1",
    author="Adam Trask (@Taskr)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Interact with Cuckoo Sandbox via API calls",
    packages=find_packages(),
    include_package_data=True,
)

