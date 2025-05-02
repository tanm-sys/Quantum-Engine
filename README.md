# Secure File Encryption Toolkit

![GitHub Build Status](https://github.com/tanm-sys/Quantum-Engine/actions/workflows/build.yml/badge.svg)
![License](https://img.shields.io/github/license/tanm-sys/Quantum-Engine)
![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![Coverage Status](https://img.shields.io/codecov/c/github/tanm-sys/Quantum-Engine)

## Table of Contents

- [Project Title & Tagline](#secure-file-encryption-toolkit)
- [Badges](#badges)
- [Table of Contents](#table-of-contents)
- [Project Overview](#project-overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Configuration & Customization](#configuration-customization)
- [Architecture & Internals](#architecture-internals)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)
- [Troubleshooting & Support](#troubleshooting-support)
- [Credits & Acknowledgments](#credits-acknowledgments)
- [License](#license)
- [Maintainers & Contact](#maintainers-contact)

## Project Overview

### Brief Elevator Pitch

The Secure File Encryption Toolkit is a comprehensive, user-friendly command-line interface (CLI) designed to provide robust file encryption, decryption, and key management capabilities. Built with security, performance, and usability in mind, this toolkit empowers users to protect sensitive data using state-of-the-art cryptographic algorithms.

### Key Features

- **Multi-Algorithm Support**: AES, CHACHA20, PostQuantum (via PyNaCl), and RSA-OAEP encryption
- **Interactive Menu System**: Rich UI with animations and styled output for an enhanced user experience
- **Automated Key Management**: ECC, symmetric, and PostQuantum key pair generation
- **ML-Driven Optimization**: Bayesian optimization for hyperparameter tuning and UCB algorithm selection
- **Compliance & Auditing**: Anomaly detection and NLP-based audit log analysis
- **Performance Monitoring**: Prometheus metrics integration
- **File Operations**: Encryption, decryption, key rotation, and secure file shredding
- **Policy Enforcement**: Encryption policies based on file type and size
- **Cross-Platform Support**: Works on Windows, macOS, and Linux

### Why It Exists / What Problem It Solves

Data breaches and unauthorized access continue to plague organizations and individuals alike. The Secure File Encryption Toolkit addresses these concerns by providing a comprehensive, easy-to-use solution for securing sensitive files. Whether you're protecting personal documents, corporate intellectual property, or complying with regulatory requirements, this toolkit offers the cryptographic strength and user-friendly interface needed to ensure your data remains secure.


## Installation

### Prerequisites

- Python 3.9 or higher
- pip package manager
- Git (for cloning the repository)

### Step-by-Step Install Commands

1. **Clone the repository:**

```bash
git clone https://github.com/tanm-sys/Quantum-Engine.git
cd Quantum-Engine
```

2. **Install dependencies:**

```bash
pip install -r requirements.txt
```

3. **Install the package (optional):**

```bash
pip install .
```

## Quick Start

### Minimal Example

Encrypt a file using the default AES algorithm:

```bash
python cli_tool.py encrypt /path/to/your/file.txt
```

Decrypt the file:

```bash
python cli_tool.py decrypt /path/to/your/file.txt.encrypted
```

Launch the interactive menu:

```bash
python cli_tool.py --menu
```

Generate an ECC key pair:

```bash
python cli_tool.py generate-key /path/to/your/key
```

## Usage

### Common Use Cases

- **File Encryption/Decryption**: Secure your sensitive documents
- **Key Management**: Generate and manage encryption keys
- **Cryptographic Operations**: Digital signatures, hashing, and MAC
- **ML Optimization**: Tune encryption parameters for optimal performance
- **Compliance Monitoring**: Detect anomalies in audit logs

### Advanced Configuration Options

- **Specify encryption algorithm:**

```bash
python cli_tool.py encrypt /path/to/file.txt --algorithm 3  # Uses PostQuantum algorithm
```

- **Enable compression before encryption:**

```bash
python cli_tool.py encrypt /path/to/file.txt --compress
```

- **Process directories recursively:**

```bash
python cli_tool.py encrypt /path/to/directory --recursive
```

- **Apply encryption policies:**

```bash
python cli_tool.py encrypt /path/to/file.txt --policy /path/to/policy.yaml
```

### Environment Variables / Flags

- `LOG_LEVEL`: Set logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `METRICS_PORT`: Port for Prometheus metrics server (default: 8000)
- `DEFAULT_ALGORITHM`: Default encryption algorithm (1-7)

## API Reference

### Public Classes

- **EncryptionCLI**: Main CLI interface for file operations
- **KeyManager**: Manages key generation and storage
- **AuditLogger**: Handles audit logging operations
- **FileHandler**: Manages file operations and backups

### Public Functions

- **encrypt_file**: Encrypts a single file
- **decrypt_file**: Decrypts a single file
- **rotate_key_file**: Rotates encryption keys for a file
- **process_directory**: Encrypts/decrypts directories recursively
- **generate_ecc_key_pair**: Generates ECC key pairs
- **generate_symmetric_key**: Generates random symmetric keys
- **generate_pq_key_pair**: Generates PostQuantum key pairs

### Code Examples

Encrypt a file programmatically:

```python
from encryption import EncryptionHandler

EncryptionHandler.encrypt_file(
    in_filename="plaintext.txt",
    out_filename="encrypted.txt",
    password="securepassword",
    algorithm="AES"
)
```

Generate an ECC key pair:

```python
from key_management import KeyManager

key_manager = KeyManager()
private_key, public_key = key_manager.generate_ecc_key_pair()
key_manager.save_key(private_key, "private_key.pem", "password")
key_manager.save_key(public_key, "public_key.pem")
```

## Configuration & Customization

### Configuration Files

- **Encryption Policies**: Define rules for algorithm selection based on file type or size in JSON/YAML format
- **Menu Configuration**: Customize the interactive menu layout and options

Example policy file (`policy.yaml`):

```yaml
policies:
  - file_extension: ".docx"
    algorithm: "AESGCM"
  - max_size: 1048576  # 1MB
    algorithm: "CHACHA20"
default_algorithm: "AES"
```

### CLI Flags

- `--algorithm`: Specify encryption algorithm (1-7)
- `--compress`: Enable file compression before encryption
- `--recursive`: Process directories recursively
- `--policy`: Path to encryption policy file
- `--metrics`: Start Prometheus metrics server
- `--log-level`: Set logging verbosity

## Architecture & Internals

### High-Level Diagram

```
+--------------------------------+
|        EncryptionCLI           |
+--------------------------------+
           |           |
+-------------------------------+
| File Operations | Key Management |
+-------------------------------+
           |           |
+-------------------------------+
| EncryptionHandler | KeyManager |
+-------------------------------+
           |           |
+-------------------------------+
| Compliance | Cryptanalysis | ML |
+-------------------------------+
```

### Module Layout

- **cli_tool.py**: Main CLI interface and interactive menu
- **encryption.py**: File encryption/decryption operations
- **key_management.py**: Key generation and management
- **compliance.py**: Security compliance and auditing
- **cryptanalysis.py**: Cryptanalysis simulations
- **crypto_extras.py**: Additional cryptographic features
- **performance_optimizer.py**: ML-based optimization
- **utils.py**: Utility functions and helpers

## Contributing

### How to Contribute

1. **Fork the repository** and clone it locally:

```bash
git clone https://github.com/your-username/Quantum-Engine.git
cd Quantum-Engine
```

2. **Create a feature branch**:

```bash
git checkout -b feature/your-feature
```

3. **Develop your feature** and write tests

4. **Run tests** to ensure everything works:

```bash
pytest tests/
```

5. **Submit a pull request** with a clear description of your changes

### Pull Request Guidelines

- Ensure all tests pass before submitting
- Write descriptive commit messages
- Update documentation for new features
- Reference any related issues in your PR description

### Code of Conduct

Read our [Code of Conduct](CODE_OF_CONDUCT.md) to understand our commitment to fostering an inclusive community.

## Roadmap

### Upcoming Features

- **GUI Interface**: Desktop application for non-command-line users
- **Cloud Integration**: Support for encrypting files in cloud storage
- **Hardware Security**: TPM and HSM integration
- **Advanced Key Exchange**: X25519 and ECDH implementations
- **Extended Cryptanalysis**: More sophisticated attack simulations

### Milestones

- **v1.1**: GUI interface and cloud integration
- **v1.2**: Hardware security module support
- **v1.3**: Expanded cryptanalysis capabilities

## Frequently Asked Questions (FAQ)

### How secure is this toolkit?

The toolkit uses industry-standard cryptographic algorithms including AES, CHACHA20, and PostQuantum cryptography. When used correctly, it provides strong protection against modern threats.

### Can I use this for commercial purposes?

Yes! The toolkit is released under the MIT License, which allows for both personal and commercial use.

### How do I report a vulnerability?

Please report security vulnerabilities to our maintainers at [security@quantum-engine.com](mailto:tanmayspatil2006@gmail.com).

## Troubleshooting Support

### Common Errors & Fixes

- **"File not found" error**: Verify the file path and filename
- **"Invalid password"**: Double-check your password entry
- **"Algorithm not supported"**: Ensure you're using a valid algorithm number (1-7)
- **"Key generation failed"**: Check your system's entropy source

### Where to File Issues

Report bugs and feature requests in the [GitHub Issues](https://github.com/tanm-sys/Quantum-Engine/issues) section of the repository.

## Credits & Acknowledgments

Special thanks to the open-source communities behind:

- [PyCryptodome](https://pycryptodome.readthedocs.io)
- [Cryptography.io](https://cryptography.io)
- [PyNaCl](https://pynacl.readthedocs.io)
- [Bayesian Optimization Library](https://github.com/fmfn/BayesianOptimization)

## License

This project is licensed under the terms of the MIT License. See [LICENSE](LICENSE) for more details.

## Maintainers & Contact

- **Tanmay Patil** ([tanmay@quantum-engine.com](mailto:tanmayspatil2006@gmail.com))
- GitHub: [tanm-sys](https://github.com/tanm-sys)

For general inquiries, contact us at [info@quantum-engine.com](mailto:tanmayspatil2006@gmail.com).
