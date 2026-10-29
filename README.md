# Security Operations & Threat Hunting Lab

A hands-on cybersecurity project focused on investigating Windows authentication logs, identifying potential brute-force attacks, and automating security detection using Splunk and Python.

## Project Overview

This lab simulates a SOC investigation where suspicious authentication activity is analyzed using Splunk Enterprise and Python.

The project demonstrates how security analysts can detect repeated failed login attempts, investigate successful authentications, and generate reports to support incident triage.

## Tools and Technologies

- Splunk Enterprise
- Splunk Search Processing Language (SPL)
- Python 3
- Windows Authentication Event IDs 4624 and 4625
- Git and GitHub
- Visual Studio Code

## Project Features

- Analyze simulated Windows authentication events
- Detect five or more failed logins within five minutes
- Identify successful logins following repeated failures
- Automate security log analysis using Python
- Export detection findings to CSV
- Document investigation results and recommended actions

## Investigation Results

The lab identified nine failed authentication attempts against the `admin` account from source IP `198.51.100.23`, followed by a successful login from the same IP.

This activity represents a simulated potential brute-force attack and demonstrates how authentication events can be correlated to identify suspicious behavior.

## Running the Python Detector

From the project root directory, run:

```bash
python scripts/analyze_logins.py
```

The program reads the synthetic authentication data from `data/soc_windows_auth_sample.csv` and generates an alert report at `reports/detection_results.csv`.

## Splunk Setup

Import the CSV dataset into Splunk Enterprise, then run the included SPL queries.

The queries use `index=main` and `sourcetype=soc_lab`. Update these values if your Splunk configuration differs. Set the search time range to **All time** when analyzing the sample dataset.

## Detection Evidence



## Project Limitations

The dataset contains synthetic authentication events rather than live production logs. Detection thresholds are illustrative and may require tuning for a real environment.

The Splunk correlation query counts prior failures across the selected search period, while the Python detector uses a rolling five-minute window.

## Future Improvements

- Add automated unit tests
- Build a Splunk detection dashboard
- Analyze larger datasets
- Integrate additional Windows event types
- Improve detection tuning and reduce false positives

## Disclaimer

All authentication data and investigation scenarios in this repository are simulated for educational purposes.