# Miner Detector

This repository contains the source code for a **Cybersecurity course project** focused on detecting unauthorized resource usage for cryptocurrency mining.

A large number of malware programs exploit system resources to mine cryptocurrencies. This project targets **Monero mining**, as it relies solely on **CPUs and GPUs**, making it a frequent choice for malicious actors.

## 🔍 Project Components

This project is divided into the following parts:

- **CLI Scanner**  
  Scans processes and system logs for suspicious activity.

- **Demon Tool**  
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

## CLI Scanner

## Demon Tool

*(To be implemented)*

## Browser Extension

*(To be implemented)*
