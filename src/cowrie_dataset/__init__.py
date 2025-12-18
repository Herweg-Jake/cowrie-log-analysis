"""
Cowrie Dataset - Honeypot log analysis and ML dataset generation

This package processes Cowrie honeypot logs, extracts behavioral features,
applies MITRE ATT&CK labels, and stores session-level data in Elasticsearch
for ML training and threat analysis.

Inspired by the AI@NTDS paper (Wang et al., 2022) but built for our own
honeypot data from 2020-2021.
"""

__version__ = "0.1.0"
