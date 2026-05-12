# AI Misuse Detection and Explainable Reporting System

An AI-driven cybersecurity platform designed to detect sensitive data exposure, analyze risky AI interactions, and generate explainable security reports for Shadow AI environments.

## Overview

With the rapid adoption of Generative AI tools in workplaces, employees often unknowingly expose:
- API keys
- passwords
- internal documents
- confidential code
- database credentials

This project focuses on detecting and analyzing unsafe AI interactions before they become security incidents.

The system combines:
- Sensitive data detection
- Risk classification
- Behavioral analysis
- Explainable reasoning
- Forensic-style reporting

to provide better visibility into AI misuse and data exposure risks.

---

## Core Features

- Sensitive data detection using pattern analysis
- Prompt risk classification engine
- Explainable risk reasoning
- AI misuse monitoring
- Structured security logging
- Forensic-style report generation
- Modular cybersecurity architecture

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI |
| Language | Python |
| Detection Engine | Regex + Rule-based Analysis |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript |
| API Testing | Postman |
| Version Control | Git & GitHub |

### Planned Additions
- Machine Learning based anomaly detection
- NLP-based intent analysis
- JWT authentication
- PostgreSQL integration
- Docker deployment

---

## Project Architecture

```text
Frontend (HTML/CSS/JS)
          ↓
FastAPI Backend
          ↓
Detection Engine
          ↓Behavior Analyzer
          ↓
Risk Scoring Engine
          ↓
Explainable Report Generator
          ↓
SQLite Database
