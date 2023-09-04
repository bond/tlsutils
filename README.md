# tlsutils
Useful utilities for working with TLS/Certificates.

Currently only provides "tlsinfo" util.

## Installation
Can be installed from PyPi: `pip install tlsinfo`

## Usage
First domain is used as Common-name in addition to DNS-name: `tlsinfo www.google.com`

For more help: `tlsinfo --help`

## Development
To test the development version use command in repository dir: `pip install -e $(pwd)`

Pull requests are welcome :)

### Uploading package
Uploading package to PyPi

- Build package for upload: `python setup.py bdist_wheel`
- Upload package: `twine upload dist/package-version.whl`
