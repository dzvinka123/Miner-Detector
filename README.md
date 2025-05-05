# Miner Detector

This repository contains the source code for a **Cybersecurity course project** focused on detecting unauthorized resource usage for cryptocurrency mining.

A large number of malware programs exploit system resources to mine cryptocurrencies. This project targets **Monero mining**, as it relies solely on **CPUs and GPUs**, making it a frequent choice for malicious actors.

## 🔍 Project Components

This project is divided into the following parts:

- **CLI Scanner**  
  Scans processes and system logs for suspicious activity.

- **Daemon Tool**  
  Runs in the background to monitor applications, network traffic, and the usage of CPUs and GPUs.

- **Browser Extension**  
  Detects JavaScript-based miners in web pages.

---

## ⚙️ Pre-commit Hook Setup

This repository includes a `.pre-commit-config.yaml` file to enforce consistent code formatting and linting. To configure it:

1. **Install `pre-commit` locally** using one of the following commands:

   ```bash
   pip install pre-commit
   # or
   python3 -m pip install pre-commit
   # or (if using conda)
   conda install -c conda-forge pre-commit
   ```
2. **Install Git hooks** so that `pre-commit` runs automatically on `git commit`
   
   ```bash
   pre-commit install
   ```
3. (Optional) **Run checks** on all files manually:
   
   ```bash
   pre-commit run --all-files
   ```

## ⚙️ Python Package

There is a `pyproject.toml` file in the main repository directory, which is used to create a Python package. To use the scanner, it is recommended to install it beforehand. You can install and use the scanner via several methods depending on your preferred environment setup.

### Option 1: Using pip directly

```bash
pip install -r requirements.txt
pip install .
```

### Option 2: Using a virtual environment (venv)

1. Create and activate a virtual environment:

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

2. Install the package:

    ```bash
    pip install -r requirements.txt
    pip install .
    ```

### Option 3: Using Conda

1. Create and activate a conda environment:

    ```bash
    conda create -n cli-scanner python=3.11
    conda activate cli-scanner
    ```

2. Install the package:

    ```bash
    conda install pip
    pip install -r requirements.txt
    pip install .
    ```

## 📁 Structure

```bash
Miner-Detector/
├── pyproject.toml             # Project metadata and dependencies
├── README.md
├── requirements.txt           # List of dependencies
├── start_server.sh            # Shell script to start the server
├── pytest.ini                 # Pytest configuration file

├── src/
│   ├── core/
│   │   ├── processes_logs_scanner.py  # Scans logs and running processes
│   │   └── utils.py           # Helper and utility functions
│   ├── extensions/
│   ├── main.py                # Main entry point
│   └── services/
│       ├── cli.py             # CLI scanner
│       ├── daemon.py          # Background daemon logic for the scanner
│       └── web-server/
│           └── server.py      # Flask server implementation

├── tests/
│   └── unittests/
│       └── core/
│           └── test_utils.py  # Unit tests for utils.py
```

## CLI Scanner

The CLI Scanner is implemented in the `/src/services/` directory. While it can be executed directly with Python, it's **recommended to install the Python package first** for easier use via the command line.

### 🚀 How to Run

The script accepts several optional flags:

- `--proc` — Scan running processes
- `--gpu` — Check GPU usage for anomalies
- `--cpu` — Check CPU usage for anomalies
- `--logs` — Scan system logs
- `--dir` — Scan some particular directory
- `--url [URL]` — Analyze a specific URL
- `--js [FILE]` — Scan a JavaScript file
- `--time [DURATION]` for the time period to scan (e.g., 24h, 7d, 1m, etc.)

Here is an example how the scanner can be run.

```bash
cli-scanner scan --proc --cpu --gpu --logs
  --url https://example.com --js example.js --time 7d
```

## Daemon Tool

The Daemon tool is implemented in the `/src/services/` directory and is responsible for **periodic background scanning**. Just like the CLI scanner, it’s best to install the package first for convenient usage from the command line.

### 🚀 How to Run

Daemon mode by default enables background execution of process monitoring, logging, and CPU/GPU scanning. It also supports two additional arguments for configuring periodic execution, along with an option for network scanning.

- `--network [IFACE|IP]` — Inspect network activity
- `--duration [SECONDS]` — Total runtime duration of the daemon (default: 300 seconds)
- `--int [SECONDS]` — Interval between scans (default: 30 seconds)

Here is an example how the scanner can be run. This command runs the scanner in the background for 10 minutes, scanning every 60 seconds.

```bash
cli-scanner daemon --network 127.0.0.1 --duration 600 --int 60
```

## Browser Extension

*(To be implemented)*

## 🧪 How to run tests

Unit tests are located in the tests directory and primarily cover functions from utils.py.
To execute the tests, simply run:

```bash
pytest
```