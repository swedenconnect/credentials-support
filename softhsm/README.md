![Logo](https://github.com/swedenconnect/technical-framework/blob/master/img/sweden-connect.png)

# credentials-support

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Example application of how to use SoftHSM to test your PKCS#11 credentials.

---

* [Dockerfile](Dockerfile) - Example Docker file illustrating on how to install the pkcs11-tool and how to copy software based keys to the "device".

* [setup-tokens.sh](scripts/setup-tokens.sh) - Example script that initializes the device and copies credentials.

* [build.sh](scripts/build.sh), [run.sh](scripts/run.sh) - Scripts for building and running the test application.

Copyright &copy; 2020-2024, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).