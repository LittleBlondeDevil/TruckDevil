from setuptools import setup, find_packages
import os


def read(*paths):
    """Build a file path from *paths* and return the contents."""
    with open(os.path.join(*paths), 'r') as f:
        return f.read()


setup(
    name='truckdevil',
    version='1.0.0',
    description='J1939 testing framework',
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    url='https://github.com/LittleBlondeDevil/TruckDevil',
    download_url='https://pypi.org/project/truckdevil',
    license='GPLv3+',
    author='Hannah Silva',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Scientific/Engineering',
        'Topic :: Security',
    ],
    install_requires=[
        'pyserial>=3.5',
        'python-can>=3.3.4',
        'dill>=0.3.4',
    ],
    packages=find_packages(exclude=['tests*']),
)
