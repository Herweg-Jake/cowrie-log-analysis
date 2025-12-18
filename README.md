# Cowrie Dataset Pipeline

A pipeline for processing Cowrie honeypot logs into ML-ready datasets with MITRE ATT&CK labeling.

## Overview

This project processes raw Cowrie honeypot logs (JSON-lines in `.gz` files) and:

1. **Parses** events from compressed log files
2. **Aggregates** events into complete attack sessions
3. **Extracts** 52 behavioral features (message-based, host-based, geography-based)
4. **Labels** sessions with MITRE ATT&CK tactics and threat levels
5. **Stores** session documents in Elasticsearch for analysis and ML training

Inspired by the [AI@NTDS paper](https://ieeexplore.ieee.org/document/9780124) (Wang et al., 2022) but built for our own honeypot data.

## Quick Start

### 1. Install Dependencies

```bash
cd cowrie-dataset
python -m venv venv
source venv/bin/activate
pip install -e .
```

### 2. Run MVP Test (No ES Required)

```bash
# Test with a single file
python scripts/run_mvp_test.py /path/to/cowrie.json.2021_1_9.gz --print

# Test with a directory (first 10 files)
python scripts/run_mvp_test.py /opt/honeypot/ssh-amsterdam --limit 10 --print
```

### 3. Set Up Elasticsearch (Optional)

```bash
# Set vm.max_map_count (required for ES)
sudo sysctl -w vm.max_map_count=262144

# Start ES + Kibana
cd docker
docker-compose up -d
```

### 4. Configure Environment

```bash
cp .env.example .env
# Edit .env with your settings
```

### 5. Run Full Pipeline

```bash
# Process one location
python -m cowrie_dataset.cli --location ssh-amsterdam --limit 10 --create-index

# Process all locations
python -m cowrie_dataset.cli --all

# Dry run (no ES writes)
python -m cowrie_dataset.cli --location ssh-amsterdam --limit 5 --dry-run --print-docs
```

## Project Structure

```
cowrie-dataset/
├── src/cowrie_dataset/
│   ├── parsers/           # Log file parsing
│   │   └── cowrie_parser.py
│   ├── aggregators/       # Session aggregation
│   │   └── session_aggregator.py
│   ├── features/          # Feature extraction
│   │   ├── message_features.py   # F1-F38
│   │   ├── host_features.py      # F39-F46
│   │   └── geo_features.py       # F47-F52
│   ├── labeling/          # MITRE ATT&CK labeling
│   │   └── mitre_labeler.py
│   ├── sinks/             # Data storage
│   │   └── elasticsearch_sink.py
│   ├── config.py          # Settings management
│   └── cli.py             # Command-line interface
├── scripts/
│   └── run_mvp_test.py    # Standalone test script
├── docker/
│   └── docker-compose.yml # ES + Kibana setup
├── tests/                 # Unit tests (TODO)
└── notebooks/             # Analysis notebooks (TODO)
```

## Features

### Message-Based (F1-F38)
Features extracted from command inputs:
- Invalid commands (bash, shell, exit, help)
- Account operations (passwd, useradd)
- File execution (./file, sh, perl, python, /bin/)
- Permission escalation (chmod, sudo su)
- History deletion (rm, history -c)
- System reconnaissance (uname, cat /etc/, ps, free)
- Network commands (wget, curl, tftp, scp)
- Impact commands (kill, reboot)
- Obfuscation (base64, hex encoding)
- Content metrics (message length, commands/sec)

### Host-Based (F39-F46)
Connection and protocol information:
- Protocol (SSH vs Telnet)
- Source port
- SSH client version/family
- Username/password
- Session duration
- File downloads/uploads

### Geography-Based (F47-F52)
Attacker location (requires GeoLite2):
- Continent, country, region, city
- Latitude/longitude

## Labeling System

Sessions are labeled with threat levels based on MITRE ATT&CK tactics:

| Level | Severity | Tactics |
|-------|----------|---------|
| 1 | High | Impact, Execution, Command & Control, Defense Evasion |
| 2 | Medium | Persistence, Privilege Escalation, Credential Access |
| 3 | Low | Discovery, No Action |

## Session Types

- `failed_auth_only`: Never successfully authenticated
- `success_no_commands`: Logged in but ran no commands
- `success_with_commands`: Logged in and executed commands

## Configuration

Environment variables (set in `.env`):

| Variable | Description | Default |
|----------|-------------|---------|
| `ES_HOST` | Elasticsearch URL | `http://localhost:9200` |
| `ES_USER` | ES username (optional) | |
| `ES_PASSWORD` | ES password (optional) | |
| `ES_INDEX_PREFIX` | Index name prefix | `cowrie-sessions` |
| `HONEYPOT_DATA_DIR` | Path to honeypot logs | `/opt/honeypot` |
| `GEOLITE_DB_PATH` | Path to GeoLite2-City.mmdb | |
| `BULK_SIZE` | Docs to buffer before bulk index | `500` |
| `LOCATIONS` | Comma-separated locations or `all` | `all` |

## Data Directory Layout

Expected layout for honeypot data:

```
/opt/honeypot/
├── ssh-amsterdam/
│   ├── cowrie.json.2020_10_1.gz
│   ├── cowrie.json.2020_10_2.gz
│   └── ...
├── ssh-bangalore/
│   └── ...
├── ssh-london/
│   └── ...
└── ...
```

## Elasticsearch Index

Session documents include:
- Session metadata (ID, location, timing)
- Connection info (IPs, ports, protocol)
- Client info (SSH version, hassh)
- Authentication data (attempts, success, credentials)
- Commands (inputs, counts)
- Downloads/uploads
- All 52 features
- Labels (level, tactics)
- Geographic data

## Next Steps

1. **Add geo enrichment**: Download GeoLite2-City.mmdb from MaxMind
2. **Create Kibana dashboards**: Sessions/day, top IPs, tactic distribution
3. **Export training dataset**: CSV/Parquet for ML
4. **Train models**: LightGBM, Random Forest, etc.
5. **Scale up**: Process full dataset across all locations

## License

MIT
