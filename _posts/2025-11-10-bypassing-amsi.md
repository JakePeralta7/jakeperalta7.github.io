---
layout: post
date: 2025-11-02
tags: [malware, windows, amsi]
---

## Bypassing AMSI

AMSI (Antimalware Scan Interface) is a Windows standard introduced in Windows 10 which allows interpreters to integrate with Antimalware products.

To integrate AMSI, the interprter's developer needs to call the AMSI scan API with the script snippet prior to its execution and act according to the results.

### Architecture

Consumer: Scripting Engine (interpreter), can be any application.

Provider: Security Products registered to AMSI.

Windows provides the glue - amsi.dll that interfaces the AMSI API.

<img width="727" height="321" alt="image" src="https://github.com/JakePeralta7/jakeperalta7.github.io/blob/main/assets/amsi7archi.jpg?raw=true"/>

### Consumers

Here is a list of Windows components that integrates with AMSI out of the box:
- User Account Control (UAC)
- PowerShell
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

### References
[MSDN - Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/en-us/windows/win32/AMSI/antimalware-scan-interface-portal)
[CrowdStrike - Patchless AMSI Bypass](https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/)
