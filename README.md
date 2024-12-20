# SOC Project: Simple SOC Homelab with Azure. Threat Detection with Azure Sentinel 🚀

Welcome to the SOC (Security Operations Center) Project repository! This project demonstrates how to set up and manage a SOC environment using **Azure Sentinel**, **Sysmon**, and **Windows Event Logs** to detect and respond to simulated threats.

---

## **Project Overview**
This project focuses on:
- Setting up Azure Sentinel as a SIEM.
- Collecting telemetry using Sysmon and Windows Event Logs.
- Simulating real-world attack scenarios.
- Crafting KQL queries for effective detection.
- Creating an interactive SOC workbook for monitoring.

---

## **Table of Contents**
1. [Environment Setup](#environment-setup)
2. [Threat Simulations](#threat-simulations)
3. [KQL Queries](#kql-queries)
4. [SOC Workbook](#soc-workbook)
5. [Screenshots](#screenshots)

---

## **Environment Setup**
### Tools and Platforms
- **Azure Sentinel**: Cloud-based SIEM for centralized logging and monitoring.
- **Sysmon**: Advanced telemetry collection for process creation, network activity, etc.
- **Windows Server VM**: Source of logs (Sysmon + Security Events).
- **Linux VM**: Used for attack simulations (e.g., RDP brute force with Hydra).

### Data Sources
- **WindowsEvents Table**: Logs from Sysmon and Windows Defender.
- **Event Table**: Core Windows Security Event Logs.

- ![RL9FJ_im3BtdKrWz_Nw7xi_42I6qYN5YWqEbxUorNXSjSwR41GRQTyUjIDaGERInt_Ep_PHf50pI79o9Uyj737Y0kCFAlrckOOikqWLI-iFHCx4KSd84WKf1hXqP8rOqKRmym08tC0lbpegYJI2OMwors9ZI-QQ2RFQXsGm-3UZf5R_pKEZTChaCCFR1R-h2rp1ZT2UnPOIr3_jun9Aq](https://github.com/user-attachments/assets/609b9163-bfff-47f2-a297-e770f75db7d4)
- ![VLAzRi903DxlAQnCxO3O6IeOoWGJAWnL1oivqXCNEpfVe53rtUjBI9IYg9bY-_knFzrI8eROLDx8oL6D0IkGJopuugY48tgneqdELSraAUxYrLi8Dez8fRV6H1UriU4IrfulS0nSmNuh41bsYdTalJ74XONiu4ZbHSSPe82M-ory6z3lwFm8y7fMPjAKR6Awkqh517uOloVt5Q6_HfSB](https://github.com/user-attachments/assets/e81f3b26-420e-4f57-a93a-fb6120093821)
- ![TP3DJiCm3CVlVWgh9pYiT1CFC0J73GwLojbhJOcMEbFYQ7oexuv1QbK4yyt-V_oYR9DIr3nuI4Sd9ueqO7gbBfoTzFX2Fl52QSDm2iAYjRvxniYjalIU0TIf7UgdUzpH0HzPpo4UyS5HRpc0reVSON7taICN-0be8w5ZB2ooQim_NMtcNfEVdTXRqghE1s75gtLLLkMwh6usjzVBo5Gu](https://github.com/user-attachments/assets/95da3e89-300d-4bca-9c04-d38943b4afa9)

---

## **Threat Simulations**
Simulated attack scenarios included:
1. **RDP Brute Force**:
   - Simulated failed logins with Hydra.
   - Logs: Event ID **4625** (failed logins) and **4740** (account lockouts).
2. **Malware Detection**:
   - Used the EICAR test file to trigger Windows Defender.
   - Logs: Event ID **1116**.
3. **Process Creation**:
   - Spawned processes with suspicious command-line arguments.
   - Logs: Sysmon Event ID **1**.
4. **Registry Modifications**:
   - Added persistence keys.
   - Logs: Sysmon Event ID **13**.
5. **PowerShell Execution**:
   - Executed base64-encoded commands.
   - Logs: Sysmon Event ID **4104**.
6. **Network Activity**:
   - Simulated connections to suspicious IPs and ports.
   - Logs: Sysmon Event ID **3**.


![PP512zf048Nl-olcgAVUaqDD5Q7KYYPIw34aBt5mCnjcTv7uwxjhX1Pw2Soyzxu9RtS-j1hYP8r_iCojjXFvi5YahtBtLipROug6fsZR0AeF5_gcCO2EJZkKfgYZqCKzeSqTrjBUJLChlK_AJzVpi52DaHDneS4fNQ0-JP1tTg_8q2RwcJjsqTEHBLBsxy4pmjFf8t55q0LsacJ30srk](https://github.com/user-attachments/assets/a4441a7d-8b05-47ad-b945-2eb41d751ba7)

---

## **KQL Queries**
Explore the `queries.md` folder for all KQL queries used in this project.

### Example Query: Failed Logins
```kql
Event
| where EventID == 4625
| extend TargetAccount = extract(@"<Data Name='TargetUserName'>(.*?)</Data>", 1, EventData),
         SourceIP = extract(@"<Data Name='IpAddress'>(.*?)</Data>", 1, EventData)
| summarize FailedAttempts = count() by TargetAccount, SourceIP, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| order by FailedAttempts desc
```
### Example Query: Process Creation Logs
```kql
WindowsEvents
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 1
| extend ParentProcess = tostring(EventData.ParentImage), CommandLine = tostring(EventData.CommandLine)
| project TimeGenerated, Computer, ParentProcess, CommandLine
```




## **SOC Workbook**
The workbook visualizes telemetry from:

- Failed logins.
- Malware detections.
- Process creation.
- Registry changes.
- Network activity.
- Features
- Event Overview: Summary of key events.
- Detailed Tables: Process creation, network connections, and registry changes.
- Visualizations: Bar charts, line graphs, and KPIs for quick insights.

Workbooks are use to create visualizations for custom dashboards



## **Screenshots**

![image](https://github.com/user-attachments/assets/f9caf048-a5cf-4c54-82c1-f8b026db7c4c)
Screenshot of a dashboard tailored on windows "Event" telemetries


![image](https://github.com/user-attachments/assets/655bb00b-2ed6-4077-af1d-d9efcffec738)
![image](https://github.com/user-attachments/assets/22696ca2-2bf3-4b41-baee-2fe04d1f13db)

Screenshots of a separate dashboard tailored on "windows Sysmon" logs
