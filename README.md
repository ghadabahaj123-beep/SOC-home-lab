# SOC Home Lab — SIEM Detection Engineering

A hands-on Security Operations Center (SOC) home lab built to develop and demonstrate
practical detection engineering skills across two industry SIEM platforms: the
**ELK Stack** (Elasticsearch, Logstash, Kibana) and **Splunk**.

The lab covers the full detection pipeline — log collection, parsing and normalization,
detection rule development, and alerting — and validates each detection against
real, simulated attacks generated from an attacker VM.

---

## Objective

Build a working SOC monitoring environment from scratch and use it to author,
tune, and validate detections for common Windows attack techniques. The lab was
built twice — first on ELK, then rebuilt on Splunk — to demonstrate transferable
detection-engineering skills rather than dependence on a single tool.

---

## Lab Architecture

```
┌─────────────────────┐         ┌──────────────────────┐        ┌─────────────────────┐
│   Kali Linux VM     │  attack │  Windows Server 2019 │  logs  │   Splunk / ELK      │
│   (Attacker)        │────────▶│  VM (Victim)         │───────▶│   (SIEM)            │
│   192.168.56.102    │         │  192.168.56.101      │        │   Docker on host    │
└─────────────────────┘         └──────────────────────┘        └─────────────────────┘
        │                                │                                │
        │      VirtualBox Host-Only Network (192.168.56.0/24)            │
        └────────────────────────────────┴────────────────────────────────┘
```

| Component | Role | Details |
|-----------|------|---------|
| Windows Server 2019 VM | Victim / log source | Ships Windows Event Logs to the SIEM |
| Kali Linux VM | Attacker | Generates real authentication attacks over the network |
| SIEM (Splunk / ELK) | Detection & alerting | Runs in Docker on the host |
| Host-Only Network | Connectivity | Isolated `192.168.56.0/24` segment between VMs |

---

## Platforms

This repository contains two parallel lab builds:

- **[`/splunk`](./splunk)** — Splunk Enterprise deployment with Universal Forwarder log
  shipping and scheduled correlation-search alerts.
- **[`/elk`](./elk)** — ELK Stack deployment with Winlogbeat log shipping, Logstash
  ECS normalization, and Kibana detection rules.

---

## ELK → Splunk Skills Mapping

A core goal of this lab was to show that SIEM detection-engineering skills transfer
across platforms. The same detection was built on both stacks; only the tooling and
query language differ.

| Function | ELK Stack | Splunk |
|----------|-----------|--------|
| Log shipping agent | Winlogbeat | Universal Forwarder |
| Parsing / field extraction | Logstash (`mutate`, `rename` filters) | `props.conf` / `transforms.conf` |
| Field normalization | ECS (Elastic Common Schema) | CIM (Common Information Model) |
| Query language | Lucene / KQL | SPL (Search Processing Language) |
| Detection rule | Kibana threshold detection rule | Scheduled correlation search |
| Alerting | Kibana alerting | Triggered Alerts / alert actions |
| Data store | Elasticsearch index | Splunk index |

---

## Detection: Brute-Force / Failed Logon (Event ID 4625)

The lab's primary detection identifies brute-force authentication attempts by
counting failed logon events (Windows Event ID **4625**) per account within a
time window.

**MITRE ATT&CK:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
(Tactic: Credential Access, TA0006). The ELK build adds a second, behavioral
detection for a **successful** RDP logon as Administrator — flagging a likely
compromise when a brute-force attempt succeeds.

### SPL (Splunk)

```spl
index=main sourcetype=WinEventLog:Security EventCode=4625
| bucket _time span=5m
| stats count as failed_attempts,
        values(Logon_Type) as logon_types,
        values(Workstation_Name) as source_host,
        values(Sub_Status) as failure_codes
        by _time, Account_Name, Source_Network_Address
| where failed_attempts >= 5
| eval severity="High"
```

**Detection logic:** groups failed logons into 5-minute windows per account and
source, and triggers when 5 or more failures occur inside a single window — the
signature of a brute-force attempt, distinct from occasional legitimate mistyped
passwords.

**Enrichment fields** make each alert actionable rather than just a count:

- `Source_Network_Address` — the attacker's IP address
- `Logon_Type` — how the attempt was made (2 = local/interactive, 3 = network, 10 = RDP)
- `Sub_Status` — *why* the logon failed, which distinguishes attack types:
  - `0xC0000064` — the account does not exist → **user enumeration**
  - `0xC000006A` — account exists, wrong password → **password guessing**

### Validation

The detection was validated against real attacks launched from the Kali VM:

- **Local attempts** (`runas`) produced `Logon_Type 2` events from loopback (`::1`).
- **Network attempts** (SMB brute-force via `netexec`/`nxc` against port 445)
  produced `Logon_Type 3` events carrying the attacker's real IP, `192.168.56.102`.

The scheduled alert fired on every 5-minute interval that contained an attack,
logging High-severity triggered alerts with full attribution (source IP, target
account, logon type, and failure reason).

---

## Skills Demonstrated

- SIEM deployment and configuration (Splunk Enterprise, ELK Stack) via Docker
- Endpoint log collection (Universal Forwarder, Winlogbeat) and forwarder-to-indexer
  connectivity troubleshooting
- Windows Event Log analysis and Event ID interpretation
- Field normalization concepts (ECS / CIM)
- Detection engineering: threshold-based rules, correlation searches, alert tuning
- Detection validation through adversary simulation (SMB brute-force from Kali)
- Cross-platform skills transfer (ELK ↔ Splunk)

---

## Repository Structure

```
soc-home-lab/
├── README.md              # This file
├── splunk/
│   ├── README.md          # Splunk lab detailed writeup
│   ├── detection-rules/   # SPL queries
│   └── screenshots/       # Evidence
└── elk/
    ├── README.md          # ELK lab detailed writeup
    └── screenshots/        # Evidence
```

---

*Built as a self-directed portfolio project for SOC Analyst roles.*
