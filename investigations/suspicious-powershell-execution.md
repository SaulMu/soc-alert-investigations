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
