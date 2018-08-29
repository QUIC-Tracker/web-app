from setuptools import setup, find_packages

retval = setup(
    name='quic-tracker',
    version='0.1',
    packages=find_packages(),
    url='https://github.com/QUIC-Tracker/web-app',
    license='GNU AGPL v3',
    author='Maxime Piraux',
    author_email='',
    description='A web application for visualising quic-tracker test results',
    install_requires=['flask', 'PyYAML', 'sqlobject', 'quic-tracker-dissector'],
    dependency_links=['https://github.com/QUIC-Tracker/dissector.git#egg=quic-tracker-dissector'],
    include_package_data=True,
)
