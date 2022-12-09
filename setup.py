from distutils.core import setup

setup(
    name='capstool',
    version='3.0',
    packages=['capstool'],
    url='https://github.com/alexander-hanel/capstool',
    author='ahanel',
    author_email='alexander.hanel@gmail.com',
    install_requires=['capstone','pefile'],
)
