# -Azure-Honeypot-Microsoft-Sentinel-Attack-Map

# Azure Honeypot & Microsoft Sentinel Attack Map

This lab project demonstrates a real-world honeypot deployment on Microsoft Azure and integrates Microsoft Sentinel for centralized log collection, threat detection, and attack visualization.

---

## Overview

I deployed a Windows 10 virtual machine in Azure, configured it as a honeypot, and simulated brute-force login attempts to generate Event ID 4625 logs. Logs were collected through Log Analytics and analyzed using KQL within Microsoft Sentinel. I enriched the data using a custom IP geolocation watchlist and built a dynamic attack map to visualize logins by region.

---

## Environment and Tools

| Component                  | Purpose                                             |
|----------------------------|-----------------------------------------------------|
| Azure Virtual Machine      | Honeypot endpoint to simulate attacks               |
| Network Security Group     | Inbound rule configuration to allow open traffic    |
| Windows Firewall           | Disabled to mimic a vulnerable asset                |
| Event Viewer               | Captured local security logs (Event ID 4625)        |
| Microsoft Sentinel         | SIEM for central log collection and analysis        |
| Log Analytics Workspace    | Aggregated logs, enabled KQL search capability      |
| KQL (Kusto Query Language) | Used to filter and correlate security events        |
| Sentinel Watchlist         | Imported GeoIP data to enrich attacker IPs          |
| Sentinel Workbooks         | Visualized real-time attack sources on a map        |

---

## Lab Objectives

- Deploy and configure a honeypot VM on Azure
- Generate and capture security events via failed login attempts
- Connect VM logs to Microsoft Sentinel using AMA
- Use KQL to query failed login events (Event ID 4625)
- Enrich logs with geolocation data via a custom watchlist
- Create a workbook with an attack map to visualize source locations

---

## Sample Queries

```kql
SecurityEvent
| where EventID == 4625
| where IpAddress != ""


let GeoIPDB = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoIPDB, IpAddress, network);
WindowsEvents
