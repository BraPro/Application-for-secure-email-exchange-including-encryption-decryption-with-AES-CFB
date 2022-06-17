from setuptools import setup, find_namespace_packages

dependencies = [
    'dataclasses'
]

setup(
    name='Email Application Cryptology',
    author="Group-29",
    packages=find_namespace_packages(),
    install_requires=dependencies,
    python_requires='>=3.6'
)
