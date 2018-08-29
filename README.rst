A web app for visualising QUIC-Tracker
======================================

The web application is a Python Flask application that presents the test results in an human-readable way.

It is known to be working with Python 3.6, but it should be compatible with earlier Python 3 versions.

Installation
------------

- ``pip3 install --upgrade git+https://github.com/QUIC-Tracker/dissector git+https://github.com/QUIC-Tracker/web-app``
- Fetch web dependencies using ``yarn install`` in ``quic_tracker/static``
- Output files from the test suite should be placed into `quic_tracker/traces` with a name in the format `\d*.json`
