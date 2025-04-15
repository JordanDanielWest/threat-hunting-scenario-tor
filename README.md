<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/JordanDanielWest/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I searched the DeviceFileEvents table for any string with the word ‘tor’ in it and discovered that the user ‘ds9-cisco’ downloaded and installed a tor browser and created several tor related documents on the desktop and created a text file titled “tor-shopping-list.txt” on the desktop at 2025-04-14T21:18:38.2736577Z. These events began at: 2025-04-14T21:01:37.1940431Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains "tor"
| where DeviceName == "edr-machine"
| where InitiatingProcessAccountName == "ds9-cisco"
| where Timestamp >= datetime(2025-04-14T21:01:37.1940431Z)
| sort by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/351bd797-4e4e-453b-881e-5c8b4795bced)

---

### 2. Searched the `DeviceProcessEvents` Table

I searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string ‘tor-browser-windows-x86_64-portable-14.0.9.exe’. Based on the logs returned on April 14, 2025, at 4:04:58 PM Central Time, the user "ds9-cisco" on device "edr-machine" silently executed the file tor-browser-windows-x86_64-portable-14.0.9.exe from the Downloads folder. The SHA-256 hash of the file is af243ca521ac0f02b21082dcbe1e6e87dc575797baf6e970530b6c0d1bfd5384, which matches the official hash provided by the Tor Project for this version, confirming its authenticity.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "edr-machine"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.9.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/8a68b6f8-5ccf-434e-a9d6-382a96c9c206)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I searched the DeviceProcessEvents table for any indication that user "ds9-cisco" actually opened the Tor browser. There was evidence that they opened it at this time: 2025-04-14T21:05:30.6659937Z. There were several other instances of ‘firefox.exe’(Tor) as well as ‘tor.exe’ spawned afterwards.
**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "edr-machine"
| where FileName has_any ("tor.exe", "torbrowser.exe", "start-tor-browser.exe", "tor-browser.exe", "firefox.exe", "tor-browser-windows-x86_64-portable-14.0.9.exe")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, FolderPath, SHA256
| sort by Timestamp desc

```
![image](https://github.com/user-attachments/assets/e15501c2-18bb-44b6-bc2e-555786bc53d1)


### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworksEvents table to determine if the Tor browser was used to establish a connection using any of the known Tor ports. On April 14, 2025, at 4:05:53 PM Central Time, the user “ds9-cisco” on device “edr-machine” initiated a successful connection from the Tor Browser's Firefox executable to the local SOCKS proxy at 127.0.0.1:9150. This indicates that the Tor Browser was actively routing traffic through its internal proxy.

**Query used to locate events:**

```kql
DeDeviceNetworkEvents
| where DeviceName == "edr-machine"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051","9150", "80", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath
| sort by Timestamp desc
```
![image](https://github.com/user-attachments/assets/8f4b15e7-0d26-4c51-8f9d-e9bfbc355ccf)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-14T21:01:37.1940431Z`
- **Event:** The user "ds9-cisco" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.9.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\DS9-CISCO\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-04-14T21:04:58.6035812Z`
- **Event:** The user "ds9-cisco" executed the file `tor-browser-windows-x86_64-portable-14.0.9.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.9.exe /S`
- **File Path:** `C:\Users\DS9-CISCO\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-04-14T21:05:30.6659937Z`
- **Event:** User "ds9-cisco" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\DS9-CISCO\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-04-14T21:05:38.1904337Z`
- **Event:** A network connection to IP `194.147.140.107` on port `443` by user "ds9-cisco" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\ds9-cisco\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-04-14T21:05:40.7830533Z` - Connected to `116.12.180.234` on port `443`.
  - `2025-04-14T21:06:46.2718388Z` - Local connection to `194.147.140.107` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "ds9-cisco" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-04-14T21:18:38.2736577Z`
- **Event:** The user "ds9-cisco" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\DS9-CISCO\Desktop\tor-shopping-list.txt`

---

## Summary

The user "ds9-cisco" on the "edr-machine" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `edr-machine` by the user `ds9-cisco`. The device was isolated, and the user's direct manager was notified.

---# threat-hunting-scenario-tor
