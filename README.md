# Intelligent SOC Incident Analysis Platform

## Overview

The **Intelligent SOC Incident Analysis Platform** is a real-time Security Operations Center (SOC) solution that combines traditional SIEM technologies with **Generative Artificial Intelligence (LLM)** and **Machine Learning** to automate the detection, correlation, reconstruction, analysis, and visualization of cybersecurity incidents.

The platform integrates:
- **Wazuh** for security monitoring and alert generation.
- **Apache Kafka** for real-time event streaming.
- **Machine Learning (Isolation Forest)** for anomaly detection.
- **Mistral LLM (via Ollama)** for explainable incident analysis and SOC recommendations.
- **FastAPI** for REST API and WebSocket communication.
- **React.js** with Material UI and Recharts for interactive dashboards.
- **SQLite** for lightweight incident persistence.


## Objectives

- Collect and process Wazuh security alerts in real time.
- Correlate multiple security events into unified incidents.
- Reconstruct attack scenarios and timelines.
- Map incidents to the MITRE ATT&CK framework.
- Generate AI-powered incident summaries and recommendations.
- Detect anomalous behavior using Machine Learning.
- Visualize incidents through an interactive SOC dashboard.
- Provide real-time monitoring and incident management.


## System Architecture

```text
                    +----------------------+
                    |    Wazuh Agents      |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    |  wazuh_to_kafka.py   |
                    +----------+-----------+
                               |
                               v
                Kafka Topic: security-alerts
                               |
                               v
                    +-----------------------+
                    | correlation_engine.py |
                    +----------+------------+
                               |
                               v
              Kafka Topic: security-incidents
                               |
                               v
                +-------------------------------+
                | incident_reconstructor.py      |
                +---------------+---------------+
                                |
                                v
        Kafka Topic: reconstructed-incidents
                                |
                +---------------+---------------+
                |                               |
                v                               v
      +--------------------+        +-----------------------------+
      |   ml_analyzer.py   |        | llm_analyzer_realtime.py    |
      | (Isolation Forest) |        | (Mistral + Ollama)          |
      +----------+---------+        +-------------+---------------+
                 |                                |
                 +---------------+----------------+
                                 |
                                 v
                  Kafka Topic: final-incidents
                                 |
                                 v
                       +-------------------+
                       |   SQLite Database |
                       +---------+---------+
                                 |
                                 v
                         +---------------+
                         |   FastAPI API |
                         +-------+-------+
                                 |
                  +--------------+--------------+
                  |                             |
                  v                             v
          REST API (/incidents)        WebSocket (/ws/incidents)
                                 |
                                 v
                    +--------------------------+
                    |    React Dashboard        |
                    +--------------------------+
```

---

## Main Features

### Backend
- Real-time Wazuh alert collection.
- Kafka-based event streaming pipeline.
- Security event correlation engine.
- Incident reconstruction and timeline generation.
- MITRE ATT&CK mapping.
- SQLite-based incident storage.
- JSON incident export.
- Incident status management (Open / Closed / Reopen).

### Artificial Intelligence
- AI-generated incident summaries.
- Explainable AI (XAI).
- AI-powered SOC recommendations.
- Risk explanation and confidence scoring.

### Machine Learning
- Isolation Forest anomaly detection.
- Machine Learning anomaly scoring.
- Top anomaly ranking.
- Detection of abnormal incident patterns.

### Dashboard
- Real-time incident monitoring.
- Threat evolution visualization.
- Severity distribution.
- Attack type distribution.
- Incident status overview.
- Machine Learning behavior distribution.
- Top priority incidents.
- Top ML anomaly scores.
- Detailed incident analysis page.
- Open / Close / Reopen incident workflow.

---

## Technologies Used

| Category | Technology |
|----------|------------|
| SIEM | Wazuh |
| Event Streaming | Apache Kafka |
| Backend API | FastAPI |
| Frontend | React.js |
| User Interface | Material UI |
| Data Visualization | Recharts |
| Database | SQLite |
| Large Language Model | Mistral (Ollama) |
| Machine Learning | Scikit-learn (Isolation Forest) |
| Programming Language | Python 3 |
| Communication | REST API & WebSocket |

## Project Structure

```text
soc-incident-analysis/
│
├── api.py
├── correlation_engine.py
├── db.py
├── incident_reconstructor.py
├── llm_analyzer_realtime.py
├── ml_analyzer.py
├── preprocessing.py
├── producer.py
├── test_preprocessing.py
├── wazuh_to_kafka.py
│
├── frontend/
│   ├── src/
│   │   ├── App.js
│   │   ├── App.css
│   │   ├── index.js
│   │   ├── index.css
│   │   ├── components/
│   │   │   ├── AttackMap.js
│   │   │   ├── IncidentTable.js
│   │   │   ├── MitrePanel.js
│   │   │   ├── Sidebar.js
│   │   │   ├── StatsCards.js
│   │   │   └── Topbar.js
│   │   │
│   │   └── pages/
│   │       ├── Dashboard.js
│   │       ├── Incidents.js
│   │       └── IncidentDetails.js
│   │
│   ├── public/
│   └── package.json
│
├── .gitignore
└── README.md
```


## Backend Modules

| Module | Description |
|----------|-------------|
| `wazuh_to_kafka.py` | Collects and normalizes Wazuh alerts before publishing them to Kafka. |
| `correlation_engine.py` | Correlates related alerts into unified security incidents. |
| `incident_reconstructor.py` | Reconstructs attack timelines and incident context. |
| `ml_analyzer.py` | Computes anomaly scores using the Isolation Forest model. |
| `llm_analyzer_realtime.py` | Generates AI summaries, explanations, and recommendations using Mistral. |
| `db.py` | Manages SQLite persistence and incident status updates. |
| `api.py` | Provides REST APIs and WebSocket communication for the frontend. |
| `preprocessing.py` | Contains data preprocessing utilities. |
| `producer.py` | Kafka producer utility functions. |


## Frontend Modules

### Pages

| File | Description |
|------|-------------|
| `Dashboard.js` | Main SOC dashboard with real-time statistics and charts. |
| `Incidents.js` | Displays and filters the incident list. |
| `IncidentDetails.js` | Shows detailed incident information and management actions. |

### Components

| Component | Description |
|------------|------------|
| `Sidebar.js` | Main navigation menu. |
| `Topbar.js` | Header and platform status display. |
| `StatsCards.js` | Dashboard KPI cards. |
| `IncidentTable.js` | Live incident table component. |
| `MitrePanel.js` | MITRE ATT&CK visualization panel. |
| `AttackMap.js` | Attack mapping and visualization component. |


## Dashboard Features

The dashboard provides:
- Total incident counter.
- Critical, High, Medium, and Low severity counters.
- Open incident counter.
- Machine Learning anomalous incident counter.
- Threat evolution chart.
- Machine Learning behavior distribution chart.
- Severity distribution chart.
- Attack type distribution chart.
- Incident status overview chart.
- Top priority incidents chart.
- Top Machine Learning anomaly scores chart.
- Live incident feed sorted by dynamic priority.

---

## Tested Attack Scenarios

The platform has been validated using the following attack scenarios:

| Attack Scenario | Status |
|-----------------|--------|
| SSH Brute Force (Hydra) | Completed |
| Successful SSH Login | Completed |
| Multiple Successful Logins | Completed |
| Full Kill Chain Reconstruction | Completed |
| Privilege Escalation (sudo) | Completed |
| Sensitive File Access | Completed |
| Machine Learning Anomaly Detection | Completed |

---

## Artificial Intelligence and Machine Learning

### Large Language Model (LLM)

The platform integrates the **Mistral** model through **Ollama** to:
- Generate incident summaries.
- Explain why an incident is dangerous.
- Produce SOC analyst recommendations.
- Provide Explainable AI (XAI).

### Machine Learning

An **Isolation Forest** model is used to:
- Learn normal SOC behavior.
- Detect abnormal activity patterns.
- Produce anomaly scores.
- Flag suspicious incidents independently from severity classification.

---

## Running the Project

### Backend

Start the backend services in the following order:

```bash
python3 wazuh_to_kafka.py
python3 correlation_engine.py
python3 incident_reconstructor.py
python3 ml_analyzer.py
python3 llm_analyzer_realtime.py
uvicorn api:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
npm install
npm start
```

The dashboard will be available at:

```text
http://localhost:3000
```

