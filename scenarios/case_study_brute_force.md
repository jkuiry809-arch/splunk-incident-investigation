# Incident Case Study: Brute-Force Attack Investigation

## 1. Incident Overview
* **Incident Type:** Automated Brute-Force Attack against Authentication Services.
* **Severity:** Medium / High
* **Detection Mechanism:** Splunk SIEM automated correlation query (`queries/brute_force_detection.spl`).

---

## 2. Investigation Workflow (Step-by-Step)

### Step 1: Anomaly Detection
An automated alert triggered in the SIEM indicating an abnormal spike in failed login attempts from a specific source IP address (`192.168.1.105`).

### Step 2: Query Execution & Data Extraction
Using the following SPL query, the security analyst isolated the activity to determine the scope:
```spl
index=security sourcetype=linux_auth action=failure 
| stats count as failed_attempts by src_ip user 
| where failed_attempts > 5 
| sort - failed_attempts
