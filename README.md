# RSA PKCS#1 v1.5 Signature Verification

This project implements RSA PKCS#1 v1.5 signature verification using NIST test vectors. The goal is to verify RSA signatures and ensure the correctness of cryptographic operations using standard test cases.

## Table of Contents

- [RSA PKCS#1 v1.5 Signature Verification](#rsa-pkcs1-v15-signature-verification)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Running the Tests](#running-the-tests)
  - [Implementation Details](#implementation-details)
    - [Key Components](#key-components)
  - [Files and Structure](#files-and-structure)
  - [Dependencies](#dependencies)
  - [Acknowledgments](#acknowledgments)

## Introduction

RSA PKCS#1 v1.5 is a widely used standard for RSA signature generation and verification. This project uses NIST-provided test vectors to validate the implementation of RSA signature verification. The project includes parsing of test vectors, RSA key generation, signing and verification processes, and test execution.

## Running the Tests

To run the tests, execute the `test.py` script:

```bash
python3 test.py
```

This script will parse the test vectors from `SigGen15_186-3.txt`, generate RSA keys, perform signature verification, and output the test results, indicating whether each test passed or failed.

## Implementation Details

The project is structured into several modules:

- **RSA Key Generation**: Includes functions to generate large primes, compute the modulus, and generate public/private keys.
- **Signature Generation and Verification**: Implements PKCS#1 v1.5 padding, message hashing, signing, and signature verification.
- **Test Vector Parsing**: Parses the NIST test vector file to extract test cases, including message, signature, and RSA parameters.

### Key Components

- `RSA Class`: Manages RSA key generation, signing, and verification operations.
- `NISTTestParser Class`: Parses the NIST test vectors and prepares them for execution.
- `NISTSignatureTest Class`: Runs the parsed test cases and checks the correctness of the RSA signature verification.

## Files and Structure

- `rsasignature/rsa.py`: Contains the `RSA` class with methods for key generation, signing, and verification.
- `rsasignature/keygen.py`: Provides utility functions for key generation, including prime number generation.
- `rsasignature/primality.py`: Implements primality testing algorithms.
- `test.py`: The main test script that runs the NIST test vectors.
- `SigGen15_186-3.txt`: NIST test vector file containing test cases for signature verification.

## Dependencies

This project requires Python 3.6 or higher. Other dependencies include:

- `hashlib`: For hashing messages using different SHA algorithms.

Ensure that all dependencies are installed before running the tests.

## Acknowledgments

This project uses NIST test vectors for RSA signature verification. We acknowledge the contributions of the cryptographic community in providing robust standards and test cases for secure cryptographic implementations.
