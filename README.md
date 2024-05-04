# Benchmarking Cryptography
Computer systems are never safe: they are always subject to novel ways of attacks, and hardware/software vulnerabilities. This project studies
the resistance of four types cryptographic algorithms: [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)), SHA, and Kyber against well-known hardware vulnerabilies such as row hammer 
and timing side-channel, and also evaluate emerging threats, like linear and differential cryptoanalysis, and quantum attacks. 

# Codebase
This project will utilize [OpenSSL](https://www.openssl.org), [Qiskit](https://en.wikipedia.org/wiki/Qiskit), and [Open Quantum Safe Library](https://openquantumsafe.org) to build testbench.

Each directory contains three files, here is a breakdown of the tests included:

| File          | Test          | 
| ------------- |:-------------:| 
| Protocol Encoder/Decoder (original) | 100.3MHz |
| Protocol Encoder/Decoder (this project)      | 186.82MHz      | 
| Order Book (original) | 203.98MHz     | 
| Order Book (this project) | 204.78MHz | 
| Trading Logic (original) | 265.75MHz | 
|Trading Logic (this project) | 149.74MHz | 

