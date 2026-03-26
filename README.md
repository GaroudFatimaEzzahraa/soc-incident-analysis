# PFE - SOC Incident Correlation Project

This repository contains the current implementation of my PFE project.

## Project title
Design and development of an intelligent engine for correlation and automatic reconstruction of security incidents in a SOC environment based on Wazuh, Kafka, MITRE ATT&CK and LLM.

## Current modules
- wazuh_to_kafka.py
- preprocessing.py
- test_preprocessing.py

## Current workflow
Wazuh -> alerts.json -> Kafka -> preprocessing

## Next steps
- correlation engine
- incident reconstruction
- MITRE ATT&CK enrichment
- scoring
- incident report
- recommendations
- LLM integration
