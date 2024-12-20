# KQL Queries for SOC Project

This file contains all the **KQL queries** used in the SOC project for analyzing logs in Azure Sentinel. The queries are grouped by their data sources: **Windows Event Logs (`Event`)** and **Windows Sysmon Logs (`WindowsEvents`)**.

> **Note**: The queries provided here may differ depending on your environment, as the structure of logs (e.g., `EventData`) can vary due to custom configurations.

---

## **Windows Event Queries (`Event`)**

### **1. Failed Logins**
```kql
Event
| where EventID == 4625
| extend TargetAccount = extract(@"<Data Name='TargetUserName'>(.*?)</Data>", 1, EventData),
         SourceIP = extract(@"<Data Name='IpAddress'>(.*?)</Data>", 1, EventData)
| summarize FailedAttempts = count() by TargetAccount, SourceIP, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| order by FailedAttempts desc
```

### Successful Logins
```kql
Event
| where EventID == 4624
| extend TargetAccount = extract(@"<Data Name='TargetUserName'>(.*?)</Data>", 1, EventData),
         LogonType = extract(@"<Data Name='LogonType'>(.*?)</Data>", 1, EventData)
| summarize SuccessfulLogins = count() by TargetAccount, LogonType, bin(TimeGenerated, 5m)
| order by SuccessfulLogins desc
```

### User Account Creation
```kql
Event
| where EventID == 4720
| extend NewAccountName = extract(@"<Data Name='TargetUserName'>(.*?)</Data>", 1, EventData),
         InitiatorAccount = extract(@"<Data Name='SubjectUserName'>(.*?)</Data>", 1, EventData)
| project TimeGenerated, NewAccountName, InitiatorAccount
| order by TimeGenerated desc
```

## **Windows Sysmon Queries (WindowsEvents)**

### Process Creation
```kql
WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 1
| extend ParentProcess = tostring(EventData.ParentImage),
         Process = tostring(EventData.Image),
         CommandLine = tostring(EventData.CommandLine)
| project TimeGenerated, Computer, ParentProcess, Process, CommandLine
| order by TimeGenerated desc
```

### Network Connections
```kql
WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 3
| extend DestinationIP = tostring(EventData.DestinationIp),
         DestinationPort = tostring(EventData.DestinationPort),
         Protocol = tostring(EventData.Protocol)
| project TimeGenerated, Computer, DestinationIP, DestinationPort, Protocol
| order by TimeGenerated desc
```
### Registry Changes
```kql
WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 13
| extend RegistryKey = tostring(EventData.TargetObject),
         ValueName = tostring(EventData.ValueName),
         Value = tostring(EventData.Value)
| project TimeGenerated, Computer, RegistryKey, ValueName, Value
| order by TimeGenerated desc
```

### File Creation
```kql
WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 11
| extend TargetFile = tostring(EventData.TargetFilename)
| project TimeGenerated, Computer, TargetFile
| order by TimeGenerated desc
```

### Powershell Execution
```kql
WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 4104
| extend ScriptContent = tostring(EventData.ScriptBlockText)
| project TimeGenerated, Computer, ScriptContent
| order by TimeGenerated desc
```

## Windows Defender KQL queries forwarded to Azure Sentinel

### Malware Detection
```kql
WindowsEvent
| where Provider == "Microsoft-Windows-Windows Defender" and EventID == 1116
| extend ThreatName = extract(@"Threat Name:\s*(.+?)\s*\n", 1, tostring(EventData)),
         Path = extract(@"Path:\s*(.+?)\s*\n", 1, tostring(EventData)),
         SeverityName = extract(@"Severity Name:\s*(.+?)\s*\n", 1, tostring(EventData)),
         StatusDescription = extract(@"Status Description:\s*(.+?)\s*\n", 1, tostring(EventData))
| project TimeGenerated, Computer, ThreatName, Path, SeverityName, StatusDescription
| order by TimeGenerated desc
```
