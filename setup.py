import os
from setuptools import setup

package_dir = "prop"


def split_path(path, result=None):
    if result is None:
        result = []
    head, tail = os.path.split(path)
    if head == '':
        return [tail] + result
    if head == path:
        return result
    return split_path(head, [tail] + result)


# Setup the packages names
packages = []
root_dir = os.path.dirname(__file__)
if root_dir != '':
    os.chdir(root_dir)

for dirpath, dirnames, filenames in os.walk(package_dir):
    if '__init__.py' in filenames:
        packages.append('.'.join(split_path(dirpath)))

setup(
    name='prop',
    version='0.0',
    description='My simple rop chain generator.',
    author='jofra',
    license='MIT',
    packages=packages,
    entry_points={
        'console_scripts': [
            'prop=prop.prop:main',
        ],
    })
