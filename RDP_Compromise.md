# SOC Investigation Report Template

#### RDP Compromise Incident

**Report ID:** INC-2025-XXXX  
**Analyst:** Jay Patel
**Date:** October 15, 2025  
**Incident Date:** September 14, 2025  

## 1. Findings  

### Key Indicators of Compromise (IOCs):  
- Attack Source IP: 159.26.106.84  
- Compromised Account: slflare  
- Malicious File: msupdate.exe  
- Persistence Mechanism: MicrosoftUpdateSync  
- C2 Server: 185.92.220.87  
- Exfiltration Destination: 185.92.220.87:8081  

### KQL Queries Used:  

#### Query 1 - Initial Access Detection:
```kql
DeviceLogonEvents
| where DeviceName contains "flare"
| where Timestamp >= datetime(2025-09-14T00:00:00Z)
| where LogonType != "Interactive"
| where ActionType in ("LogonSuccess", "LogonFailed")
| project Timestamp, DeviceName, ActionType, AccountName, RemoteIP, LogonType
| order by Timestamp asc
```
**Results:**  
- Revealed multiple failed logins from 159.26.106.84, followed by successful login as slflare on Sep 16, 2025 3:43:46 PM.  
<img width="1179" height="533" alt="Screenshot 2025-09-21 192602" src="https://github.com/user-attachments/assets/a1ed025f-dc9a-4432-b3d3-035b24027e95" />

#### Query 2 - Malicious Execution:
```kql
DeviceProcessEvents
| where DeviceName contains "flare"
| where Timestamp >= datetime(2025-09-16T16:38:40Z)
| where InitiatingProcessAccountName == "slflare"
| where FolderPath has_any ("\temp\", "\tmp\", "\public\", "\download", "\downloads\", "%temp%", "%public%")
| project Timestamp, FileName, ProcessCommandLine, AccountName, FolderPath
| sort by Timestamp desc
```
**Results:**  
- Detected `msupdate.exe` executed with command line `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1` on Sep 16, 2025 4:38:40 PM.  
<img width="1236" height="526" alt="Screenshot 2025-09-22 164014" src="https://github.com/user-attachments/assets/93c57f75-b725-4458-a930-e2af5a90dba5" />

#### Query 3 - Persistence Detection:
```kql
DeviceRegistryEvents
| where DeviceName contains "flare"
| where Timestamp >= datetime(2025-09-16T16:38:40Z)
| where RegistryKey contains "TaskCache"
| where ActionType == "RegistryKeyCreated"
| extend TaskName = extract(@"TaskCache\Tree\(.+?)(?:\|$)", 1, RegistryKey)
| project Timestamp, DeviceName, ActionType, TaskName, RegistryKey
| order by Timestamp asc
```
**Results:**  
- Identified scheduled task `MicrosoftUpdateSync` created on Sep 16, 2025 4:39:45 PM.  
<img width="987" height="554" alt="Screenshot 2025-09-22 164705" src="https://github.com/user-attachments/assets/2a09887b-399b-4109-89ac-2e3a24bef1eb" />

#### Query 4 - Defender Modification:
```kql
DeviceRegistryEvents
| where DeviceName contains "flare"
| where Timestamp >= datetime(2025-09-16T16:39:45Z)
| where RegistryKey has_any ("Windows Defender", "Microsoft Defender", "Exclusions", "PathExclusions")
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```
**Results:**  
- Defender exclusion added for C:\Windows\Temp on 2025-09-16T19:39:48.704946Z.  
<img width="1318" height="362" alt="Screenshot 2025-09-22 164714" src="https://github.com/user-attachments/assets/91341b36-1283-4fcf-8e85-c506c1d5fae5" />

#### Query 5 - Discovery Command:
```kql
DeviceProcessEvents
| where DeviceName contains "flare"
| where Timestamp >= datetime(2025-09-16T19:39:48.704946Z)
| where InitiatingProcessAccountName == "slflare"
| where ProcessCommandLine has_any ("systeminfo", "ipconfig", "netstat", "whoami", "hostname", "tasklist", "net view")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, FolderPath
| order by Timestamp asc
```
**Results:**  
- Discovery command `"cmd.exe" /c systeminfo` executed.  
<img width="1191" height="560" alt="Screenshot 2025-09-22 172438" src="https://github.com/user-attachments/assets/9119f399-0979-4e86-aed1-112aca6e3689" />

#### Query 6 - Archive File Creation:
```kql
DeviceFileEvents
| where DeviceName contains "flare"
| where Timestamp >= datetime(2025-09-16T19:39:48.704946Z)
| where InitiatingProcessAccountName == "slflare"
| where FileName has_any (".zip", ".rar", ".7z")
| where FolderPath has_any ("\Temp\", "\AppData\", "\ProgramData\")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by Timestamp asc
```
**Results:**  
- Archive file `backup_sync.zip` created on Sep 16, 2025 4:41:30 PM.  
<img width="1212" height="508" alt="Screenshot 2025-09-22 173932" src="https://github.com/user-attachments/assets/f5cc9308-fc56-4463-aefc-28dcfd2b2981" />

#### Query 7 - C2 Connection:
```kql
DeviceNetworkEvents
| where DeviceName contains "flare"
| where Timestamp >= datetime(2025-09-16T19:43:20.8733344Z)
| where InitiatingProcessAccountName == "slflare"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, ActionType, InitiatingProcessCommandLine, RemotePort
| order by Timestamp asc
```
**Results:**  
- C2 connection to 185.92.220.87 on Sep 16, 2025 4:43:42 PM.
 <img width="1148" height="560" alt="Screenshot 2025-10-15 121015" src="https://github.com/user-attachments/assets/2e3c8701-0174-4309-9133-f6b29c31a49d" />
 
#### Query 8 - Exfiltration Attempt:
```kql
DeviceNetworkEvents
| where DeviceName contains "flare"
| where Timestamp >= datetime(2025-09-16T19:43:20.8733344Z)
| where InitiatingProcessAccountName == "slflare"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, ActionType, InitiatingProcessCommandLine, RemotePort
| order by Timestamp asc
```
**Results:**  
- Exfiltration to 185.92.220.87:8081.
<img width="1251" height="561" alt="Screenshot 2025-09-22 175028" src="https://github.com/user-attachments/assets/e323cb98-6c4b-488a-b98c-35ac1e332785" />

## 2. Investigation Summary  

**What Happened:** The attacker performed a password spray attack on the RDP endpoint, gaining access as slflare from IP 159.26.106.84. They executed msupdate.exe to bypass policies and run update_check.ps1, created persistence with MicrosoftUpdateSync task, excluded C:\Windows\Temp from Defender, ran systeminfo for discovery, archived data as backup_sync.zip, connected to C2 server 185.92.220.87, and exfiltrated data to 185.92.220.87:8081.  

**Attack Timeline:**  
- Started: Sep 16, 2025 3:43:46 PM (UTC)  
- Ended: Sep 16, 2025 4:43:42 PM (UTC)  
- Duration: 1 hour  

**Impact Level:** High  

## 3. Who, What, When, Where, Why, How  

**Who:**  
- Attacker: 159.26.106.84 (external threat actor)  
- Victim Account: slflare (compromised username)  
- Affected System: flare-vm (hostname, IP)  
- Impact on Users: Potential data loss from HR systems  

**What:**  
- Attack Type: RDP brute force leading to system compromise  
- Malicious Activities:  
  - Password spray and login  
  - Malicious binary execution  
  - Persistence via scheduled task  
  - Defender exclusion  
  - System discovery  
  - Data archiving  
  - C2 connection  
  - Data exfiltration  

**When:**  
- First Malicious Activity: Sep 16, 2025 3:43:46 PM (UTC)  
- Last Observed Activity: Sep 16, 2025 4:43:42 PM (UTC)  
- Detection Time: October 15, 2025  
- Total Attack Duration: 1 hour  
- Is it still active? No  

**Where:**  
- Target System: flare-vm (Azure cloud VM)  

**Why:**  
- Likely to exfiltrate sensitive data, as evidenced by archiving and outbound connections.  

**How:**  
- RDP password spray (T1110.001)  
- Valid credentials access (T1078)  
- Command interpreter (T1059.003)  
- Malicious file execution (T1204.002)  
- Scheduled task persistence (T1053.005)  
- Impair defenses (T1562.001)  
- System information discovery (T1082)  
- Archive data (T1560.001)  
- Application layer protocol (T1071.001)  
- Exfiltration over unencrypted protocol (T1048.003)  

## 4. Recommendations  

- **Immediate Actions:**  
  - Isolate flare-vm from the network to prevent further exfiltration.  
  - Remove the `MicrosoftUpdateSync` scheduled task and disable the `slflare` account.  
  - Re-enable Defender scanning for C:\Windows\Temp and restore default security settings.  

- **Long-Term Mitigation:**  
  - Implement multi-factor authentication (MFA) for RDP access to prevent future password spray attacks.  
  - Monitor outbound traffic to 185.92.220.87 and block it at the firewall.  
  - Conduct regular audits of scheduled tasks and Defender exclusions.  

- **Enhancements:**  
  - Deploy advanced endpoint detection tools to identify similar malicious binaries.  
  - Train staff on recognizing phishing or social engineering attempts that may lead to credential compromise.  
  - Update password policies to enforce complexity and rotation to mitigate brute force risks.
