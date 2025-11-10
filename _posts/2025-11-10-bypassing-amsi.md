---
layout: post
date: 2025-11-02
tags: [malware, windows, amsi]
---

## Bypassing AMSI

AMSI (Antimalware Scan Interface) is a Windows standard introduced in Windows 10 which allows interpreters to integrate with Antimalware products.

To integrate AMSI, the interprter's developer needs to call the AMSI scan API with the script snippet prior to its execution and act according to the results.

### Architecture

**Consumer**: Scripting Engine (interpreter), can be any application.

**Provider**: Security Products registered to AMSI.

Windows provides the glue - amsi.dll that interfaces the AMSI API.

<img width="727" height="321" alt="image" src="https://github.com/JakePeralta7/jakeperalta7.github.io/blob/main/assets/amsi7archi.jpg?raw=true"/>

### Consumers

Here is a list of Windows components that integrates with AMSI out of the box:
- User Account Control (UAC)
- PowerShell
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

Let's implement our own consumer in C to understand the steps required.

```C
#include <windows.h>
#include <stdio.h>
#include <amsi.h>       // from Windows SDK
#include <strsafe.h>

int main(void)
{
    HAMSICONTEXT ctx = NULL;
    HAMSISESSION session = 0;
    HRESULT hr;
    AMSI_RESULT result;

    // App name (ANSI)
    const char *appName = "MyApp";
    WCHAR appNameW[64];
    MultiByteToWideChar(CP_ACP, 0, appName, -1, appNameW, ARRAYSIZE(appNameW));

    // Initialize AMSI
    hr = AmsiInitialize(appNameW, &ctx);
    if (FAILED(hr)) {
        printf("AmsiInitialize failed: 0x%08lx\n", hr);
        return 1;
    }

    // Open a session (optional)
    hr = AmsiOpenSession(ctx, &session);
    if (FAILED(hr)) {
        printf("AmsiOpenSession failed: 0x%08lx\n", hr);
        AmsiUninitialize(ctx);
        return 1;
    }

    // String to scan (ANSI)
    const char *text = "Write-Host 'Hello AMSI'";
    WCHAR textW[256];
    MultiByteToWideChar(CP_ACP, 0, text, -1, textW, ARRAYSIZE(textW));

    WCHAR contentNameW[] = L"TestInput";

    hr = AmsiScanString(ctx, textW, contentNameW, session, &result);
    if (SUCCEEDED(hr)) {
        if (AmsiResultIsMalware(result))
            printf("AmsiScanString: MALWARE detected (result=%u)\n", result);
        else
            printf("AmsiScanString: CLEAN (result=%u)\n", result);
    } else {
        printf("AmsiScanString failed: 0x%08lx\n", hr);
    }

    // Binary buffer scan example
    unsigned char buf[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    hr = AmsiScanBuffer(ctx, buf, (ULONG)sizeof(buf), contentNameW, session, &result);
    if (SUCCEEDED(hr)) {
        if (AmsiResultIsMalware(result))
            printf("AmsiScanBuffer: MALWARE detected (result=%u)\n", result);
        else
            printf("AmsiScanBuffer: CLEAN (result=%u)\n", result);
    } else {
        printf("AmsiScanBuffer failed: 0x%08lx\n", hr);
    }

    // Cleanup
    AmsiCloseSession(ctx, session);
    AmsiUninitialize(ctx);
    return 0;
}
```

### Let's Bypass!

After we have some understanding of the workflow, let's explore some ways to break it.

1. **Detection Evasion**

    For example, the AMSI provider has detection for `Write-Host "This is a Malware"`, we can run `"erawlaM a si sihT" | ForEach-Object { $a=$_.ToCharArray(); [array]::Reverse($a); -join $a } | Write-Host` instead and evade that detection.

2. **Disabling the Consumer**

   Because the AMSI functions are in user mode memory space, we can change the way it operates and render it useless.
   - We can patch the `AmsiScanBuffer` and `AmsiScanString` and always return clean result.
   - We can set hardware breakpoint on `AmsiScanBuffer` and `AmsiScanString` and VEH to handle the exception and return clean result.
   - We can find the AMSI Context address and call `AmsiUninitialize`.
   - We can hijack the AMSI dll
  
3. **Disabling the Provider**

   To register as an AMSI provider, you need to create a CLSID pointing to your DLL and key under `HKLM\Software\Microsoft\AMSI\Providers` named your CLSID.
   So, we can just remove or change that before opening the interpreter.

5. **Use PowerShell v2**

   There is no AMSI in PowerShell v2, in the same spirit we can compile our own version of later versions of PowerShell without importing AMSI.

### Detection

|Scenario|How to Detect?|
|---|---|
|AMSI Patching|Detect if there is a private copy of AMSI functions in a process|
|AMSI DLL Hijacking|Detect image load of amsi.dll from location other than "C:\Windows\System32\amsi.dll" or "C:\Windows\SysWOW64\amsi.dll"|
|Removing the Provider in the Registry|Detect Registry changes|
|Hardware Breakpoints and VEH|Detect using the debugregisters plugin in Volatility3|

### References

[MSDN - Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/en-us/windows/win32/AMSI/antimalware-scan-interface-portal)

[MSDN - AMSI API](https://learn.microsoft.com/en-us/windows/win32/api/amsi)

[CrowdStrike - Patchless AMSI Bypass](https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/)
