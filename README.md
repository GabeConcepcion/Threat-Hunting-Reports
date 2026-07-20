# Proactive Threat Hunting & Incident Write-ups

Welcome to my threat hunting repository. This project serves as a technical logbook documenting my hands-on experience analyzing endpoint telemetry, constructing advanced detection queries, and reconstructing end-to-end cyber attacks. 

Instead of relying purely on static security alerts, the investigations hosted here focus on hypothesis-driven hunting—isolating stealthy adversaries who abuse legitimate system tools and valid credentials to blend into daily business baselines.

---

## Operational Catalog

| Investigation Name | Target Environment | Core Focus & Core Tradecraft | Advanced Hunting Documentation |
| :--- | :--- | :--- | :---: |
| **Just Another Day: Dissecting RDP Compromise** | Corporate Subnet Grid | • Credential Abuse / Identity Hijacking<br>• Living off the Land (LotL)<br>• Active Data Camouflage | [View Full Report](./Just%20Another%20Day%3A%20Dissecting%20RDP%20Compromise.md/) |

---

## Core Hunting Methodology

Every report in this repository follows a structured, incident-response-aligned framework to ensure findings are actionable for defensive teams:

1. **Hypothesis Formulation:** Defining a specific attack vector or technique (mapped to the MITRE ATT&CK framework) that might bypass standard signature-based controls.
2. **Telemetry Ingestion & Filtering:** Querying structured event logs (`DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceFileEvents`) and filtering out standard environmental noise to avoid analyst fatigue.
3. **Behavioral Analysis:** Tracing process ancestry trees, monitoring network mapping activities, and identifying execution anomalies.
4. **Remediation & Detection Engineering:** Translating forensic findings into SIEM detection queries (KQL) and high-impact structural hardening strategies.

---

## Technical Toolkit

- **SIEM / Analytics Platforms:** Microsoft Sentinel, Azure Data Explorer
- **Query Languages:** Kusto Query Language (KQL)
- **Telemetry Sources:** Microsoft Defender for Endpoint (MDE), Windows Event Logs, Sysmon
- **Frameworks:** MITRE ATT&CK Enterprise Matrix
