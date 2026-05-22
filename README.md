# SentinelShield-WAF

## Overview

SentinelShield-WAF is a lightweight Web Application Firewall (WAF) and Intrusion Detection System developed using Python Flask.

The project inspects incoming HTTP requests, detects malicious traffic patterns, blocks common web attacks, logs suspicious activities, and displays attack analytics through a monitoring dashboard.

This project was developed as a cybersecurity practical/internship project to demonstrate real-world web protection concepts such as request inspection, attack signature detection, traffic monitoring, logging, and alert generation.

---

# Features

- HTTP Request Inspection
- SQL Injection Detection
- XSS Detection
- LFI Detection
- Directory Traversal Detection
- Command Injection Detection
- Rate Limiting
- Brute-force/Flood Detection
- Attack Logging
- IP Tracking
- Security Dashboard
- Attack Statistics Monitoring

---

# Technologies Used

- Python
- Flask
- HTML
- CSS
- Regex Pattern Matching

---

# Project Architecture

Client Request
↓
Request Inspection
↓
Attack Detection Engine
↓
Rate Limiting Check
↓
Logging System
↓
Dashboard Monitoring

---

# Supported Attack Detection

## SQL Injection
Example:
?id=' OR 1=1 --

## Cross-Site Scripting (XSS)
Example:
?q=<script>alert(1)</script>

## Local File Inclusion (LFI)
Example:
?file=../../etc/passwd

## Command Injection
Example:
?cmd=whoami;ls

---

# Dashboard Features

- Total attack count
- Attack category statistics
- Recent attack logs
- Security monitoring interface

---

# Installation & Setup

## Clone Repository

```bash
git clone https://github.com/yourusername/SentinelShield-WAF.git
