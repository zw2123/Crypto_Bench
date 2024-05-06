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

# Getting Started
1. Clone this repo to you local machine.
2. Install OpenSSL:[here](https://www.openssl.org/source/) is detailed info about how to insatll.<br>
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
   For Windows: please follow the [instruction](https://www.openssl.org/source/gitrepo.html) to install.<br>
   Verify installation:
   ```bash
   openssl version
   ```
2. Install Qiskit: it is recommended to set up a virtual environment to contain this, because Qiskit is evolving rapidly.<br>
   Install using pip:
   ```bash
   pip install qiskit
   ```
   Verify the installation by checking the Qiskit version:
   ```bash
   import qiskit
   print(qiskit.__qiskit_version__)
   ```
3. Install Open Quantum Safe Library:<br>
   For Linux and MacOS:<br>
   First, ensure that your system has the necessary tools and libraries:
   ```bash
   sudo apt update
   sudo apt upgrade
   sudo apt install build-essential cmake git libssl-dev
   ```
   Second, Clone and Build liboqs:
   ```bash
   git clone https://github.com/open-quantum-safe/liboqs
   cd liboqs
   mkdir build && cd build
   cmake -GNinja ..
   ninja
   sudo ninja install
   ```
   For Windows:
   Please follow instruction [here](https://github.com/open-quantum-safe/liboqs) to install and build.<br>
   Verify installation:
   ```bash
   ldconfig -p | grep liboqs
   ```
# Running Application
1. cd into one algorithm folder. <br>
   Example:
   ```bash
   cd AES
   ```
2. Compile c code: <br>
   (test_performance.c and test_security.c are compiled exactly the same way - only change the filename in commands below.) <br>
   For AES, SHA and RSA: <br>
    Example (using gcc):
   ```bash
   gcc test_performance.c -o test_performance -lcrypto -lpthread
   ```
   For Kyber:<br>
   ```bash
   gcc test_performance.c -o test_performance -lOQS -lpthread
   ```
4. Run c code: <br>
   To run test_perforamnce:
   ```bash
   ./test_performance <key  size>
   ```
   For example:
   ```bash
   ./test_performance 128
   ```
   Supported key sizes are:
   | Algorithm     | Key size      | 
   | ------------- |:-------------:| 
   |   AES         | 128; 256      |
   |   RSA         | 2048; 4096    | 
   |   SHA         | 1(160); 256   | 
   |   Kyber       | 128; 256      | 

   To run test_security:
   ```bash
   ./test_security <key  size> <test type>
   ```
   Supported test types are:
   | Test Type     | Command       | 
   | ------------- |:-------------:| 
   |   Brute Force | bruteforce    |
   |   Replication | replicated    | 
   |   Row Hammer  | rowhammer     | 
   |   Timing side-channel       | timing     | 
   |   Linear Cryptoanalysis     | linear     |
   |   Differential Cryptoanalysis | differential|

   For example:
   ```bash
   ./test_security 128 timing
   ```
5. Run python code: make sure Qiskit is installed, and/or you activate proper virtual environment.<br>
   ```bash
   python test_quantum.py <key size>
   ```
   supported key sizes are same as above.

# Extension
Follow-up works and extensions are welcomed and appreciated, this is a course project that I completed in 60 hours, many new and important test cases are not included, please clone the repo and extend the scope of the test. 
   
   
   
