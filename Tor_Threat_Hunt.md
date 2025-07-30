# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/JP-Portfolio/Threat-Hunts/blob/main/Unauthorized%20TOR%20Usage.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "jay" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `Items-ordered-tor.txt` on the desktop at `2025-07-25T16:29:24.8756333Z`. These events began at `2025-07-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "windows"  
| where InitiatingProcessAccountName == "jay"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-07-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1032" height="591" alt="Screenshot 2025-07-29 122259" src="https://github.com/user-attachments/assets/766784d9-546a-4aa8-9720-5904a564e159" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.5.exe". Based on the logs returned, at `2025-07-25T16:25:15.683201Z`, an employee on the "windows" device ran the file `tor-browser-windows-x86_64-portable-14.5.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "windows"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1152" height="573" alt="Screenshot 2025-07-29 122427" src="https://github.com/user-attachments/assets/cb7dce1e-a929-42a3-a4b5-d8cacc65cd1c" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "jay" actually opened the TOR browser. There was evidence that they did open it at `2025-07-25T16:26:12.9353473Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "windows"  
| where FileName has_any ("tor.exe", "edge.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1134" height="572" alt="Screenshot 2025-07-29 122549" src="https://github.com/user-attachments/assets/0c297b6f-c742-474e-add7-515bc838e20b" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-07-25T16:32:06.7953668Z`, an employee on the "windows" device successfully established a connection to the remote IP address `80.85.141.186` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\jay\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "windows"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe", "edge.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1102" height="568" alt="Screenshot 2025-07-29 123104" src="https://github.com/user-attachments/assets/4765ad3f-9d88-4310-9a4d-b11fe89bb607" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-07-08T22:14:48.6065231Z`
- **Event:** The user "jay" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\jay\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-07-25T16:25:15.683201Z`
- **Event:** The user "jay" executed the file `tor-browser-windows-x86_64-portable-14.5.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.5.exe /S`
- **File Path:** `C:\Users\jay\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-07-25T16:26:12.9353473Z`
- **Event:** User "jay" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\jay\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-07-25T16:32:06.7953668Z`
- **Event:** A network connection to IP `80.85.141.186` on port `9001` by user "jay" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\jay\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-07-25T16:32:31.2966175Z` - Connected to `64.65.63.40` on port `443`.
  - `2025-07-25T16:26:43.9932533Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "jay" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - Items-Ordered.txt

- **Timestamp:** `2025-07-25T16:49:40.1881208Z`
- **Event:** The user "jay" created a file named `Items-ordered-tor.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\jay\Desktop\Items-ordered-tor.txt`

---

## MITRE ATT&CK Mapping
The detected activities align with the following MITRE ATT&CK tactics and techniques:

- **Tactic**: `Command and Control (TA0011)`
  - **Technique**: `T1071 - Application Layer Protocol`
  - **Description**: The use of the TOR browser to establish connections to remote IP addresses (e.g., `80.85.141.186` on port `9001`) indicates encrypted communication over application layer protocols to evade network monitoring.
- **Tactic**: `Execution (TA0002)`
  - **Technique**: `T1204.002 - User Execution: Malicious File`
  - **Description**: The user "jay" executed the TOR installer (`tor-browser-windows-x86_64-portable-14.5.5.exe`) via a silent installation, indicating user-initiated execution of a potentially unauthorized application.

---

## Summary

The user "jay" on the "windows" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `Items-ordered-tor.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "Items-ordered-tor.txt" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `windows` by the user `jay`. The device was isolated, and the user's direct manager was notified.

---
