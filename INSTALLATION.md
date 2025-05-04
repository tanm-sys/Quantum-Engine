This document provides a step-by-step guide to installing and setting up the Secure File Encryption Toolkit on various operating systems.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Ubuntu/Debian](#ubuntu-debian)
  - [Fedora/CentOS/RHEL](#fedora-centos-rhel)
  - [macOS](#macos)
  - [Windows](#windows)
- [Post-Installation Configuration](#post-installation-configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

## Prerequisites

### System Requirements

- **Ubuntu/Debian**: 20.04 or later
- **Fedora/CentOS/RHEL**: 8 or later
- **macOS**: 11.0 (Big Sur) or later
- **Windows**: 10/11 (64-bit)

### Software Requirements

- Python 3.9 or higher
- pip (Python package manager)
- Git (for cloning the repository)

## Installation

### Ubuntu/Debian

1. **Update your package lists**:

```bash
sudo apt update
```

2. **Install Python 3.9+ and pip**:

```bash
sudo apt install -y python3 python3-pip python3-venv
```

3. **Install Git**:

```bash
sudo apt install -y git
```

4. **Clone the repository**:

```bash
git clone https://github.com/tanm-sys/Quantum-Engine.git
cd Quantum-Engine
```

5. **Create a virtual environment (recommended)**:

```bash
python3 -m venv venv
source venv/bin/activate
```

6. **Install dependencies**:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

7. **Install the toolkit**:

```bash
pip install .
```

### Fedora/CentOS/RHEL

1. **Install Python 3.9+ and pip**:

```bash
sudo dnf install -y python3 python3-pip python3-virtualenv
```

2. **Install Git**:

```bash
sudo dnf install -y git
```

3. **Clone the repository**:

```bash
git clone https://github.com/tanm-sys/Quantum-Engine.git
cd Quantum-Engine
```

4. **Create a virtual environment (recommended)**:

```bash
python3 -m venv venv
source venv/bin/activate
```

5. **Install dependencies**:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

6. **Install the toolkit**:

```bash
pip install .
```

### macOS

1. **Install Python 3.9+** (via Homebrew):

```bash
brew install python@3.9
```

2. **Install Git**:

```bash
brew install git
```

3. **Clone the repository**:

```bash
git clone https://github.com/tanm-sys/Quantum-Engine.git
cd Quantum-Engine
```

4. **Create a virtual environment (recommended)**:

```bash
python3 -m venv venv
source venv/bin/activate
```

5. **Install dependencies**:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

6. **Install the toolkit**:

```bash
pip install .
```

### Windows

1. **Install Python 3.9+**:
   - Download the installer from [python.org](https://www.python.org/downloads/)
   - Run the installer and check "Add Python to PATH"

2. **Install Git**:
   - Download the installer from [git-scm.com](https://git-scm.com/download/win)
   - Run the installer and follow the prompts

3. **Clone the repository**:
   ```bash
   git clone https://github.com/tanm-sys/Quantum-Engine.git
   cd Quantum-Engine
   ```

4. **Create a virtual environment (recommended)**:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   ```

5. **Install dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

6. **Install the toolkit**:
   ```bash
   pip install .
   ```

## Post-Installation Configuration

### Configuring Encryption Policies

1. **Create a policy file** (e.g., `policy.yaml`):

```yaml
policies:
  - file_extension: ".docx"
    algorithm: "AESGCM"
  - max_size: 1048576  # 1MB
    algorithm: "CHACHA20"
default_algorithm: "AES"
```

2. **Specify the policy file location**:
   - Use the `--policy` flag when running the toolkit
   - Or set the `ENCRYPTION_POLICY` environment variable

### Setting Up the Metrics Server

1. **Start the metrics server**:

```bash
python cli_tool.py --metrics
```

2. **Access metrics** at `http://localhost:8000` (Prometheus compatible)

## Verification

1. **Encrypt a test file**:

```bash
python cli_tool.py encrypt test.txt
```

2. **Enter a password** when prompted

3. **Verify the encrypted file** is created (`test.txt.encrypted`)

4. **Decrypt the file**:

```bash
python cli_tool.py decrypt test.txt.encrypted
```

5. **Compare the original and decrypted files**:

```bash
diff test.txt test.txt.decrypted
```

## Troubleshooting

### Common Issues

- **"Module not found" errors**:
  - Ensure you've activated your virtual environment
  - Reinstall dependencies with `pip install -r requirements.txt`

- **Permission errors**:
  - Run commands with appropriate privileges (use `sudo` if needed)
  - Ensure the toolkit directory is writable

- **Algorithm not recognized**:
  - Use valid algorithm numbers (1-7)
  - Update the toolkit to the latest version

### Logging and Diagnostics

1. **Enable debug logging**:

```bash
python cli_tool.py --log-level DEBUG
```

2. **Review logs** in `application.log`

3. **Check audit logs** in `audit.log`

## Uninstallation

### Using Pip

```bash
pip uninstall quantum-engine
```

### Manual Removal

1. **Delete the installation directory**:

```bash
rm -rf /path/to/Quantum-Engine
```

2. **Remove the virtual environment** (if used):

```bash
rm -rf venv
```

3. **Clean up dependencies**:

```bash
pip uninstall -r requirements.txt
```

## Additional Notes

- **Virtual Environment**: Using a virtual environment is recommended to avoid dependencies conflicts
