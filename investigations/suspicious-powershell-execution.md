# Alert Investigation: Suspicious PowerShell Execution

## 1. Alert Summary

**Alert Name:** Suspicious PowerShell Execution  
**Severity:** Medium / High  
**Source:** SIEM / EDR / Windows Logs  
**Host:** LAB-WIN10-01  
**User:** lab_user  
**Date:** YYYY-MM-DD

## 2. Alert Description

A suspicious PowerShell command was executed using encoded parameters. This behavior may indicate malicious script execution, defense evasion or post-exploitation activity.

## 3. Evidence

```powershell
powershell.exe -ExecutionPolicy Bypass -EncodedCommand <encoded_string>
```
Relevant indicators:

Process: powershell.exe
Parent process: cmd.exe
Command line contains: -EncodedCommand
Network connection observed: Yes / No
File created: Yes / No
4. MITRE ATT&CK Mapping
Tactic	Technique	ID
Execution	Command and Scripting Interpreter: PowerShell	T1059.001
Defense Evasion	Obfuscated Files or Information	T1027
5. Analysis

The use of -EncodedCommand can be legitimate in administrative tasks, but it is also commonly used by attackers to hide malicious PowerShell commands. The investigation should validate the user context, parent process, destination IPs, script content and any related process execution.

6. Investigation Questions
Was the command executed by an expected user?
What was the parent process?
Was the encoded command decoded and reviewed?
Did the host connect to suspicious external infrastructure?
Were additional tools downloaded or executed?
Are there related alerts from the same host or user?
7. Recommended Actions
Decode and analyze the PowerShell command.
Check related process tree.
Review network connections.
Validate user activity.
Isolate host if malicious behavior is confirmed.
Create or tune detection logic for encoded PowerShell execution.
8. Conclusion

Based on the evidence, this alert is classified as: True Positive / False Positive / Benign True Positive / Needs Further Investigation.
