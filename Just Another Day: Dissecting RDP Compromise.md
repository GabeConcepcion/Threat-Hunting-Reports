<img width="3168" height="1344" alt="Just Another Day" src="https://github.com/user-attachments/assets/d124e7fb-958d-4eb2-8d18-ab20786122e3" />
🛡️ Threat Hunt Report – Just Another Day: Dissecting RDP Compromise

## Executive Summary

During a proactive compromise assessment of the corporate network infrastructure, a highly targeted data exfiltration operation was uncovered operating under the guise of legitimate business activity. An external adversary successfully leveraged compromised corporate credentials to hijack an internal analyst's identity, establishing persistent, hands-on-keyboard interactive access via Remote Desktop Protocol (RDP). By strictly utilizing native Windows administrative utilities ("Living off the Land" tradecraft), the attacker bypassed traditional signature-based security alerts to systematically harvest cross-departmental human resources files, employee compensation schemes, and peer payroll datasets. The stolen documents were actively staged and renamed within core accounting directories to simulate standard system workflow anomalies, presenting a sophisticated evasion model designed to avoid forensic discovery.

---

## Hunt Objectives

- Isolate the scope, timeline, and execution vectors of unauthorized identity abuse across network infrastructure endpoints.  
- Differentiate benign corporate environmental noise and automated operating system processes from active threat actor tradecraft.  
- Correlate observed endpoint mechanics directly to the MITRE ATT&CK enterprise grid to build defensive detection mechanisms.  
- Formulate strategic infrastructure remediation plans to address authorization gaps, lateral movement paths, and data visibility vectors.

---

## Scope & Environment

- **Environment:** Nimbus Health Corporate Subnet Grid  
- **Data Sources:** Microsoft Sentinel Enterprise Workspace (`DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceFileEvents`)  
- **Timeframe:** 2026-03-09 → 2026-03-17

---

## 📚 Table of Contents

- [Hunt Overview](#hunt-overview)  
- [MITRE ATT&CK Summary](#mitre-attck-summary)  
- [Chronological Stage Analysis](#chronological-stage-analysis)  
  - [Stage 01: The Billing Account Compromise](#stage-01-the-billing-account-compromise)  
  - [Stage 02: Hands on the Keyboard Reconnaissance](#stage-02-hands-on-the-keyboard-reconnaissance)  
  - [Stage 03: Operational Boundary Violations](#stage-03-operational-boundary-violations)  
  - [Stage 04: Lateral Movement & Infrastructure Filtering](#stage-04-lateral-movement--infrastructure-filtering)  
  - [Stage 05: High-Value Target Data Collection](#stage-05-high-value-target-data-collection)  
  - [Stage 06: Threat Assessment & Incident Judgement](#stage-06-threat-assessment--incident-judgement)  
- [Detection Gaps & Recommendations](#detection-gaps--recommendations)  
- [Final Forensic Assessment](#final-forensic-assessment)

---

## Hunt Overview

Modern detection architectures frequently fail when an adversary stops using known malware toolkits and instead starts acting exactly like a trusted corporate employee. This investigation dissects an entry pattern where zero malicious payloads were compiled, dropped, or executed. 

The threat actor engaged in identity hijacking, exploiting the valid domain profile of a billing submissions analyst. Using this account, they logged in interactively from public external IP infrastructure and used the host machine as a proxy to execute discovery commands. The attack trajectory exposes a crucial visibility challenge: when an account moves laterally across network nodes, standard behavioral rules often overlook the traffic if the account already holds extensive legacy access rights. This hunt proves that identifying sophisticated data theft requires looking past simple folder access rules and analyzing the intent behind specific command sequences, file renaming practices, and sudden changes in user geolocation patterns.

---

## MITRE ATT&CK Summary

| Stage Component | Adversary Technique | MITRE ID | Defensive Priority |  
|:---|:---|:---|:---|  
| **Stage 01** | Valid Accounts: Domain Accounts | T1078.002 | Critical |  
| **Stage 01** | Remote Services: Remote Desktop Protocol | T1021.001 | High |  
| **Stage 02** | System Owner/User Discovery | T1033 | Medium |  
| **Stage 02** | System Network Configuration Discovery | T1016 | Medium |  
| **Stage 02** | Remote System Discovery | T1018 | Medium |  
| **Stage 03** | File and Directory Discovery | T1083 | Medium |  
| **Stage 03** | Masquerading: Match Legitimate Name or Location | T1036.005 | High |  
| **Stage 04** | Lateral Movement: Remote Services | T1021 | High |  
| **Stage 05** | Data from Local System / Shared Drive | T1005 / T1039 | High |

---

## Chronological Stage Analysis

---

### Stage 01: The Billing Account Compromise  
Focuses on identifying the compromised identity, analyzing how the unauthorized session was created, and highlighting the geographic anomalies that differentiate this activity from normal internal employee operations.

<details>  
<summary>🚩 <strong>Technical Breakdown (Flags 1 - 3)</strong></summary>

#### Hunting Objective  
Isolate the specific user environment undergoing anomalous behavior, identify the authentication mechanism utilized by the unauthorized actor, and trace the connection back to its true network source.

#### Finding  
The enterprise profile belonging to analyst `j.morris` displayed highly irregular logon telemetry, establishing long-distance interactive graphical control sessions outside standard corporate business configurations.

#### Forensic Evidence Cache

| Telemetry Element | Forensic Value |  
|:---|:---|  
| **Target Identity** | `j.morris` |  
| **Windows Logon Descriptors** | `RemoteInteractive` (Logon Type 10) |  
| **External Source Address** | `136.144.33.18` (Rogue WAN Node) |

#### Forensic Significance  
A standard billing submissions analyst operates locally from internal endpoint subnets (`10.1.0.0/24`). Discovering a `RemoteInteractive` session matching this profile that originates directly from a foreign, non-VPN public internet address rules out routine corporate operations. It indicates the account was targeted via credential stuffing, password spraying, or session hijacking, allowing an external adversary to take direct control of the workspace interface.

#### KQL Hunting Query  
```kusto  
DeviceLogonEvents  
| where TimeGenerated between (datetime(2026-03-08) .. datetime(2026-03-18))  
| where AccountName == "j.morris"  
| where ActionType == "LogonSuccess"  
| project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP  
| where RemoteIP != "168.63.129.16" and isnotempty(RemoteIP)
```

#### **Defensive Engineering Tip**

Enforce geolocation-based conditional access rules within your identity provider config. Instantly alert on or block standard administrative user logons if the connection originates from an external subnet without passing mandatory Multi-Factor Authentication (MFA) challenges.

</details>

### Stage 02: Hands on the Keyboard Reconnaissance

Filters through background operating system events to uncover the attacker's manual command history, exposing their targeted reconnaissance timeline and their ultimate network infrastructure focus.

<details>
<summary>🚩 <strong>Technical Breakdown (Flags 4 - 8)</strong></summary>

#### **Hunting Objective**

Differentiate automated background endpoint noise from manual attacker inputs, extract the exact sequence of discovery commands, and determine what infrastructure nodes the attacker targeted next.

#### **Finding**

After filtering out baseline file syncing actions, process telemetry revealed the attacker executed a quick sequence of native Windows binaries to confirm their local user access rights and identify accessible corporate network file shares.

#### **Forensic Evidence Cache**

[Telemetry Baseline Noise]: OneDrive Setup Automated File Synchronization Cleansings

**Adversary Process Trajectory (In Execution Order):**

> 1. whoami (Context Assessment)  
> 2. hostname (Host Orientation)  
> 3. net user (Local Privilege Mapping)  
> 4. net view (Network Share Discovery)  
> 5. net view \\NH-FS-01 (Target Server Mapping)  
> 6. "net.exe" view /domain:nimbus (Domain Controller Query)

**Network Reconnaissance Window:**  
The attacker spent exactly two minutes executing localized ARP.EXE -a sweeps to map out adjacent systems via the subnet's local ARP cache. This was combined with targeted nslookup.exe loops to perform reverse DNS lookups on nearby infrastructure hosts, building a clear map of the network just before moving laterally.

| Target Hostname Focus | NH-FS-01 (Central Corporate File Server) |
| :---- | :---- |

#### **Forensic Significance**

Attackers land blind when hijacking accounts. The use of manual discovery commands reveals an external human operator gathering context, as an automated script would not pause to verify local variables using separate whoami and hostname commands. By mapping the local network via the ARP cache and running reverse DNS queries against the domain, the attacker avoided generating the high traffic volume typical of standard network port scanners. This allowed them to quietly find their next high-value target: the organization's primary storage server.

#### **KQL Hunting Query**

```kusto  
DeviceProcessEvents  
| where TimeGenerated between (datetime(2026-03-08) .. datetime(2026-03-18))  
| where AccountName == "j.morris"  
| where FileName in~ ("cmd.exe", "powershell.exe", "whoami.exe", "net.exe", "arp.exe", "nslookup.exe")  
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName  
| sort by TimeGenerated asc
```

#### **Defensive Engineering Tip**

Monitor or restrict standard business accounts from running built-in network profiling tools like arp.exe, nslookup.exe, and net.exe. Create behavioral tracking exceptions that flag users who unexpectedly execute multiple discovery utilities within a short timeframe.

</details>

### Stage 03: Operational Boundary Violations

Exposes how the compromised account moved past its assigned access limits, showing the exact business records it modified and the hidden staging methods used to conceal the data theft.

<details>
<summary>🚩 <strong>Technical Breakdown (Flags 9 - 13)</strong></summary>

#### **Hunting Objective**

Track file system access histories across departmental shared folders, identify unauthorized changes to transaction records or audit trails, and uncover obfuscated files staged within accounting paths.

#### **Finding**

The hijacked account bypassed its standard submission workflows to access signed-off accounting shares, where it altered transaction records and audit files. The attacker then pulled highly sensitive information out of the human resources folder and disguised it as a standard billing exception file.

#### **Forensic Evidence Cache**

| Impacted Subdirectory | \\nh-fs-01\Billing\2026-03\Approved\ |
| :---- | :---- |
| **Accessed Transaction Document** | approved_pending_invoice_INV-664215_20260310.txt |
| **Altered Infrastructure Control Log** | review_audit_20260311.txt |
| **Disguised Staging Filename** | payroll_exception_reference_20260311.txt.txt |
| **Secondary Stolen Asset Profile** | quarterly_awards_shortlist_20260310.txt |

#### **Forensic Significance**

This phase shows clear malicious intent. A routine user mistake does not involve changing file extensions and deliberately renaming sensitive data to blend into a specific accounting directory. By naming the stolen payroll record payroll_exception_reference_20260311.txt.txt and hiding it in the billing folder, the attacker used **Active Camouflage (T1036.005)**. This tactic ensures that even if an administrator audits the folder, the file appears to be a normal system exception record. The simultaneous access of employee recognition shortlists also demonstrates a broader data harvesting operation targeting sensitive company records.

#### **KQL Hunting Query**

```kusto  
DeviceFileEvents  
| where TimeGenerated between (datetime(2026-03-08) .. datetime(2026-03-18))  
| where FolderPath has "Billing" or FolderPath has "HR"  
| where RequestAccountName == "j.morris"  
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, PreviousFileName, RequestAccountName  
| where ActionType in~ ("FileCreated", "FileRenamed", "FileModified")
```

#### **Defensive Engineering Tip**

Deploy Automated File Integrity Monitoring (FIM) and strict access control lists (ACLs) on sensitive shares. Generate high-priority alerts whenever user profiles from one department attempt to browse or modify directories belonging to another team (such as a billing user opening HR payroll repositories).

</details>

### Stage 04: Lateral Movement & Infrastructure Filtering

Tracks the attacker's lateral movement path across adjacent systems, detailing how to forensically filter out automated operating system background activity to identify real host compromises.

<details>
<summary>🚩 <strong>Technical Breakdown (Flags 14 - 15)</strong></summary>

#### **Hunting Objective**

Analyze lateral network authentication attempts initiated via remote control protocols, confirm which host nodes were actively compromised, and isolate systems running only automated background traffic.

#### **Finding**

Endpoint process logs confirmed the attacker initiated remote desktop connections targeting two separate machines on the network. Forensic analysis proved one of these hops was a red herring, displaying only automated background traffic rather than manual threat activity.

#### **Forensic Evidence Cache**

* **Identified Pivot Targets:** nh-wks-it-01, nh-fs-01  
* **Host Filtering Status (nh-wks-it-01):** **Forensic Red Herring.** The system recorded 106 separate process creation logs immediately following connection, but deep inspection confirmed all events were standard Windows background operations. The OS was simply building a user profile for a first-time login (userinit.exe, unregmp2.exe /FirstLogon, OneDriveSetup.exe). **No manual attacker actions occurred on this machine.**

#### **Forensic Significance**

During a security investigation, analyzing what an attacker *did not* do is just as critical as documenting their active compromises. While network access logs showed a successful authentication landing on the IT workstation (nh-wks-it-01), cross-referencing this with the endpoint's process history reveals the truth: the attacker logged in, watched the default desktop load, and immediately abandoned the session without typing a single command. Filtering out these automated system logs helps defenders narrow their focus to the true target node: the core file server (nh-fs-01).

#### **KQL Hunting Query**

```kusto  
DeviceProcessEvents  
| where TimeGenerated between (datetime(2026-03-08) .. datetime(2026-03-18))  
| where DeviceName startswith "nh-wks-it-01"  
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName  
| sort by TimeGenerated asc
```

#### **Defensive Engineering Tip**

Enforce the Principle of Least Privilege by disabling cross-workstation RDP paths. Standard operational workstations should never be permitted to establish direct RDP sessions to adjacent user machines unless they are originating from a designated, highly monitored administrative jump box environment.

</details>

### Stage 05: High-Value Target Data Collection

Audits the attacker's final actions once they successfully breached the primary storage server, focusing on how they mapped authorization limits and identified targeted employee records.

<details>
<summary>🚩 <strong>Technical Breakdown (Flags 16 - 18)</strong></summary>

#### **Hunting Objective**

Audit the command execution history on the central storage server, trace how user privileges were verified, and catalog every high-value target document opened by the threat actor.

#### **Finding**

Upon establishing an active session on the primary file server, the attacker checked their effective group memberships and mapped out the server's available file shares before opening targeted payroll records belonging to other employees.

#### **Forensic Evidence Cache**

| Executed Privileges Query | "whoami.exe" /groups |
| :---- | :---- |
| **Executed Resource Enum Query** | "net.exe" share |
| **Exfiltrated Employee Target File** | payroll_review_dpatel_20260311.txt |

#### **Forensic Significance**

By running "whoami.exe" /groups and "net.exe" share as soon as they reached the file server, the attacker verified their exact permission levels and identified all accessible directories on the host machine. The immediate opening of targeted employee files like payroll_review_dpatel_20260311.txt confirms this was a deliberate data harvesting operation. The attacker focused specifically on high-value personal data, moving far beyond the access needs of a standard billing submission role.

#### **KQL Hunting Query**

```kusto  
DeviceProcessEvents  
| where TimeGenerated between (datetime(2026-03-08) .. datetime(2026-03-18))  
| where DeviceName has "nh-fs-01"  
| where AccountName == "j.morris"  
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine  
| sort by TimeGenerated asc
```

#### **Defensive Engineering Tip**

Set up data loss prevention (DLP) alerts to monitor file share access patterns. Implement immediate alerts for scenarios where a single user account rapidly views or downloads multiple high-value, sensitive files (such as files containing string matches for payroll, compensation, or ssn) across different network directories.

</details>

### Stage 06: Threat Assessment & Incident Judgement

Provides a comprehensive summary of the incident, outlining the full scope of the stolen data and delivering an evidence-backed assessment of the root cause.

<details>
<summary>🚩 <strong>Technical Breakdown (Flags 19 - 20)</strong></summary>

#### **Hunting Objective**

Synthesize all collected endpoint, process, and file telemetry to define the true scope of the data breach and determine the exact root cause of the intrusion.

#### **Finding**

The incident summary confirms a serious data breach involving company-wide compensation structures, employee evaluation files, and individual payroll records. The evidence completely rules out an accidental internal mistake or automated malware infection.

#### **Forensic Evidence Cache**

| Breached Data Footprint | Organization-wide compensation logs, merit reviews, peer payroll files, and internal recognition shortlists. |
| :---- | :---- |
| **True Incident Vector Root Cause** | External threat actor driving a compromised valid domain account via remote interactive sessions from public internet IP addresses. |
| **Defensive Gap Indicator** | Complete absence of malware payloads or software exploitation attempts due to the exclusive use of valid, pre-compromised credentials throughout the intrusion lifecycle. |

#### **Forensic Significance**

This case highlights the challenges of defending against identity-based attacks. The complete lack of traditional compromise indicators such as exploit signatures, custom malware tools, or suspicious scripts proves the attacker intentionally chose a stealthy approach designed to blend into daily network operations. The geographical anomalies (logins from public WAN IPs) combined with active data camouflage tactics (renaming the stolen files) confirm this was a planned corporate espionage operation. The attacker successfully turned a standard, trusted internal account into a silent launchpad for data theft.

#### **KQL Hunting Query**

```kusto  
// Unified Compromise Timeline Audit Query  
DeviceLogonEvents  
| where AccountName == "j.morris" and ActionType == "LogonSuccess" and LogonType == "RemoteInteractive"  
| join kind=inner (  
    DeviceProcessEvents  
    | where AccountName == "j.morris" and FileName in~ ("whoami.exe", "net.exe", "arp.exe")  
) on AccountName, DeviceName  
| project TimeGenerated, DeviceName, AccountName, RemoteIP, ProcessCommandLine
```

#### **Defensive Engineering Tip**

Transition the enterprise architecture toward a strict Zero Trust framework. Mandate phishing-resistant Multi-Factor Authentication (MFA) across all remote access entry points, eliminate legacy cross-department access permissions, and utilize User and Entity Behavior Analytics (UEBA) to automatically flag abnormal data access patterns.

</details>

## **Detection Gaps & Recommendations**

### **Observed Defensive Gaps**

* **Identity Geolocation Vulnerability:** The enterprise network allowed external, public internet connections to establish direct Remote Desktop sessions using standard user profiles without enforcing location-based perimeter blocking.  
* **Excessive Departmental Access Rights:** The compromised account held excessive historical access rights, allowing a standard billing analyst to browse and modify confidential HR and executive directories without triggering permission errors.  
* **Discovery Tool Visibility Gaps:** The endpoint configuration lacked alerts for the command-line execution of native system utilities (whoami, net view, arp), which allowed the attacker to map out the network infrastructure completely undetected.  
* **File Obfuscation Evasion:** Security tools failed to flag anomalous file behavior, allowing the attacker to change file extensions and rename sensitive records to hide them inside unrelated transaction folders.

### **Strategic Recommendations**

* **Enforce Phishing-Resistant MFA:** Mandate the use of hardware keys or context-aware push notifications across all Remote Desktop endpoints and external access points.  
* **Implement Zero Trust Access (Microsegmentation):** Restrict legacy folder permissions across corporate shares. Ensure cross-department directories such as HR and financial repositories require explicit privilege elevation and separate manager approval checks.  
* **Deploy Living-off-the-Land (LotL) Detections:** Create behavioral rules within your EDR/SIEM tools to look for rapid successions of native Windows discovery binaries (whoami, hostname, net user, arp -a) when run by non-administrative accounts.  
* **Enable File Renaming & Extension Monitoring:** Set up automated alerts to watch for irregular file renames and double extension modifications (such as .txt.txt) within critical shared folders to detect active data staging techniques early.

## **Final Forensic Assessment**

The forensic evidence collected during this threat hunt confirms a targeted identity-based attack that bypassed traditional signature defenses by using **Living off the Land** techniques. By exploiting valid, pre-compromised user credentials from an external network connection, the attacker moved quietly through the infrastructure to target sensitive corporate information. The discovery of active data camouflage by hiding stolen payroll records inside billing transaction directories proves the actor possessed strong technical skills and a clear plan to evade detection. Protecting against these types of stealthy, identity-focused threats requires moving past basic static alerts and embracing automated behavioral analytics, continuous endpoint visibility, and a strict Zero Trust security model.
