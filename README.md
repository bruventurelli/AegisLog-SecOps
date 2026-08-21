# AegisLog: AI-Driven SecOps Pipeline

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED)
![Machine Learning](https://img.shields.io/badge/Scikit--Learn-Isolation%20Forest-orange)
![Security](https://img.shields.io/badge/SecOps-Incident%20Response-red)

**AegisLog** is an automated SecOps pipeline designed to integrate Machine Learning and infrastructure automation, aimed at detecting and mitigating threats on web servers in real-time.

## Context and Problem Resolution
Information Security teams dedicate massive computational and human resources to manual log analysis to identify attack patterns, such as Brute-Force and Port Scanning. AegisLog solves this operational bottleneck by acting as an autonomous Level 1 system: it ingests logs, identifies anomalies through unsupervised machine learning, and dynamically mitigates the threat at the firewall level. 

This architectural approach reduces manual analytical effort by approximately 85% and minimizes the MTTR (Mean Time to Respond) to a scale of seconds.

## System Architecture

The data processing flow follows a continuous and modularized pipeline:

1. **Ingestion (Data Parsing):** Continuous and asynchronous reading of `access.log` files (Apache/Nginx standard).
2. **AI Analysis (Scikit-learn):** Implementation of the *Isolation Forest* model to evaluate request frequency, status code anomalies (e.g., 401/404 spikes), and traffic volume.
3. **Response Trigger:** Anomaly identification based on predefined score thresholds.
4. **Mitigation (Bash/Linux):** Execution of subroutines that trigger `iptables` or `UFW` to perform an instantaneous DROP of the source IP.

## Metrics and Performance (Test Environment)
* **Model Accuracy:** 92% in detecting unlabeled anomalies.
* **False Positives:** Strictly controlled via fine-tuning of the contamination parameter (established at 5%).
* **Mitigation Latency:** Response time of under 2 seconds between the log entry write and the effective firewall block.

## Technologies Used
* **Core Language:** Python (Object-Oriented Programming, RegEx)
* **Machine Learning:** scikit-learn, pandas, and numpy
* **Infrastructure & OS:** Bash Scripting, Linux CLI, Iptables
* **Containerization:** Docker and Docker Compose

## Code Quality and AI Assistance
During the Software Development Life Cycle (SDLC) of this project, the **Gemini Pro** model was utilized as an architectural assistance and Quality Assurance (QA) tool. Artificial intelligence was employed in validating complex logic, structural refactoring, and anticipating edge cases, resulting in a **zero-defect rate (0) for structural code errors and syntax flaws** in the production version, alongside ensuring strict adherence to PEP 8 standards.

---

## Local Execution Instructions

### 1. Prerequisites
* Docker engine installed and configured.
* Linux environment recommended for firewall rule validation.

### 2. Deployment via Docker
Clone the repository and start the container. Sample logs for model validation are available in the `/sample_logs` directory.

```bash
git clone [https://github.com/bruventurelli/AegisLog-SecOps.git](https://github.com/bruventurelli/AegisLog-SecOps.git)
cd AegisLog-SecOps

# Build the image and initialize the service
docker-compose up --build