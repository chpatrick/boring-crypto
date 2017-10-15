[![Build Status](https://travis-ci.org/chpatrick/boring-crypto.svg?branch=master)](https://travis-ci.org/chpatrick/boring-crypto)

Haskell cryptographic primitive library based on [BoringSSL](https://boringssl.googlesource.com/boringssl/).

## Advantages

* Operations are exposed using [conduit](https://github.com/snoyberg/conduit#readme), allowing for streaming.
* All cryptographic operations are implemented in BoringSSL, no custom crypto code.
* Type-safe bindings thanks to [inline-c](https://github.com/fpco/inline-c/blob/master/inline-c/README.md).
* Tested using [pyca/cryptography](https://github.com/pyca/cryptography)'s [test suite](https://cryptography.io/en/latest/development/test-vectors/).

## Implemented features
* Symmetric encryption

  Ciphers:
  * AES128
  * AES256

  Block cipher modes:
  * ECB
  * CBC
  * OFB

* Hashing
  * MD4
  * MD5
  * SHA1
  * SHA224
  * SHA256
  * SHA384
  * SHA512

* HMAC with the above hashes

* Random number generation
