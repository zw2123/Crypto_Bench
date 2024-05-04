# Benchmarking Cryptography
Computer systems are never safe: they are always subject to novel ways of attacks, and hardware/software vulnerabilities. This project studies
the resistance of four types cryptographic algorithms: [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)), SHA, and Kyber against well-known hardware vulnerabilies such as row hammer 
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
