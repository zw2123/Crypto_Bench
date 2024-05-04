# Benchmarking Cryptography
Computer systems are never safe: they are always subject to novel ways of attacks, and hardware/software vulnerabilities. This project studies
the resistance of four types cryptographic algorithms: [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)), [SHA](https://en.wikipedia.org/wiki/Secure_Hash_Algorithms), and [Kyber](https://en.wikipedia.org/wiki/Kyber) against well-known hardware vulnerabilies such as row hammer 
and timing side-channel, and also evaluate emerging threats, like linear and differential cryptoanalysis, and quantum attacks. 

# Codebase
This project will utilize [OpenSSL](https://www.openssl.org), [Qiskit](https://en.wikipedia.org/wiki/Qiskit), and [Open Quantum Safe Library](https://openquantumsafe.org) to build testbench.

Each directory contains three files, here is a breakdown of the tests included:

| File          | Test          | 
| ------------- |:-------------:| 
| test_performance.c | encryption/decryption time |
| test_performance.c | throughput                 | 
| test_performance.c | CPU time                   | 
| test_security.c    | replication                | 
| test_security.c    | row hammer                 | 
| test_security.c    | timing side-channel        | 
| test_security.c    | linear cryptoanalyisis     |
| test_security.c    | differential cryptoanalysis|
| test_security.c    | brute force                |
| test_quantum.py    | Shor's/Grover's attack     |

# Prerequisites
- Python 3.7 or higher
- C/C++ Compiler (GCC or Clang)
- Git
- Make (for building OpenSSL)

# Get Started
1. Clone this repo to you local machine.
2. Install OpenSSL:
   For linux: use package manager: 
   ```bash
   sudo apt-get update
   sudo apt-get install libssl-dev
   ```
   For MacOS: use Homebrew:
   ```bash
   brew update
   brew install openssl
   ```
   For Windows: please follow the [instruction](https://www.openssl.org/source/gitrepo.html) to install.
   Verify installation:
   ```bash
   openssl version
   ```
   
