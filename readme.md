# Network Scanning and Exploitation Tool

This project is a Python-based tool designed for network reconnaissance and penetration testing. It leverages Nmap for
network scanning and Metasploit for exploitation tasks, providing an automated pipeline for cybersecurity assessments.

---

## Features

- **Host Discovery**: Identifies active hosts in the target network.
- **Port Scanning**: Finds open ports on discovered hosts.
- **Vulnerability Scanning**: Uses Nmap scripts to identify vulnerabilities.
- **Exploit Automation**: Searches and executes Metasploit exploits for detected vulnerabilities.

---

## Prerequisites

Ensure the following tools and libraries are installed:

1. **Python** (3.8+)
2. **Nmap**
3. **Metasploit Framework**
4. Required Python packages:

   Install dependencies by running:
   ```bash
   pip install -r requirements.txt
   ```

### 2. Configure Environment Variables

Create a `.env` file in the root directory with the following content:

```dotenv
LLM_MODEL=gpt-4o
LLM_API_TYPE=azure
LLM_API_KEY=<your_api_key>
LLM_API_VERSION=2024-02-01
LLM_AZURE_ENDPOINT=<your_azure_endpoint>
```

Update the values as per your configuration.

## Setup

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd <repository_name>
   ```

2. Set up the environment variables:

    - Define the required configurations for LLMs in a configuration file.
    - Ensure the `results` directory exists in the project root for saving scan results.

---

## Usage

Run the tool using the command-line interface with the following options:

```bash
python main.py -t <target> [--nmap] [--exploit]
```

### Arguments

- `-t`, `--target`: Specifies the target IP or IP range (e.g., `192.168.0.0/24`).
- `--nmap`: Performs Nmap scans on the target.
- `--exploit`: Executes exploitation tasks after scanning (default: enabled).

### Examples

1. **Run only an Nmap scan:**
   ```bash
   python main.py -t 192.168.0.0/24 --nmap
   ```

2. **Run a full scan and exploitation process:**
   ```bash
   python main.py -t 192.168.0.1 --exploit
   ```

---

## Project Structure

```
|-- modules/
|   |-- CONSTANTS.py          # Predefined constants for Nmap options
|   |-- configs.py            # Configuration loader
|   |-- data_formatter.py     # Data processing utilities
|   |-- utils.py              # Helper functions
|-- results/                  # Directory for saving scan results
|-- main.py   # Main script
|-- requirements.txt          # Python dependencies
```

---

## Workflow

1. **Host Discovery**:
    - Uses the `host_finder_agent` to identify active hosts in the network.

2. **Open Port Scanning**:
    - Uses the `open_ports_finder_agent` to scan for open ports on discovered hosts.

3. **Vulnerability Scanning**:
    - Leverages Nmap scripts for vulnerability detection.

4. **Exploitation**:
    - Searches for appropriate Metasploit modules and executes them against the target.

---

## Logging

The tool logs all activities to a SQLite database (`logs.db`).

---

## Known Issues

1. Ensure the target IP or range is valid and reachable.
2. Metasploit commands may fail if the database is not initialized.

---
