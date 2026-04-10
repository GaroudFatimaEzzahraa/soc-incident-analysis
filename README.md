# SOC Incident Analysis Platform

## Overview
This project implements an intelligent Security Operations Center (SOC) pipeline designed to detect, correlate, reconstruct, and analyze security incidents using Artificial Intelligence.


## Architecture
Wazuh → Kafka → Preprocessing → Correlation → Reconstruction → LLM → API


## Features

### Data Pipeline
- Alert collection using Wazuh SIEM
- Streaming via Apache Kafka
- Preprocessing and normalization

### Incident Processing
- Alert correlation engine
- Incident reconstruction with timeline
- MITRE ATT&CK enrichment

### AI Analysis
- Local LLM integration (Mistral via Ollama)
- Automated incident analysis
- Risk assessment and recommendations

### Backend
- FastAPI for exposing incident data

## Project Structure

- `wazuh_to_kafka.py` → Stream alerts from Wazuh  
- `preprocessing.py` → Normalize and clean alerts  
- `correlation_engine.py` → Correlate events  
- `incident_reconstructor.py` → Build structured incidents  
- `llm_analyzer.py` → AI-based analysis  
- `api.py` → Backend API  
- `final_report.json` → Final enriched incidents  


## Example Output

Each incident contains:
- Attack type  
- Severity  
- Timeline  
- MITRE ATT&CK techniques  
- AI-generated analysis  
- Security recommendations  


## Objective
- Reduce alert fatigue in SOC environments  
- Automate incident understanding  
- Improve response time using AI  


## Current Status
- Preprocessing completed  
- Correlation engine implemented  
- Incident reconstruction completed  
- MITRE ATT&CK integration completed  
- LLM-based analysis implemented  
- FastAPI backend implemented  
- React dashboard in progress  

