# Sigma Rules Lab

A practical **Detection Engineering and Incident Response portfolio project** focused on building, documenting, and validating portable Sigma-style detections against realistic but synthetic security telemetry.

The goal is not to collect rules for volume. It is to demonstrate a repeatable engineering lifecycle: define the threat behavior, identify required telemetry, write a focused analytic, test expected matches, document false positives, and describe how an analyst should validate an alert.

## Detection engineering lifecycle

```text
Threat / ATT&CK Hypothesis
        ↓
Required Telemetry
        ↓
Detection Logic
        ↓
Synthetic Test Events
        ↓
Expected Match Validation
        ↓
False-Positive Analysis
        ↓
Triage Guidance
        ↓
Tuning / Version Control
```

## Initial detections

| Detection | ATT&CK context | Defensive objective |
|---|---|---|
| Suspicious PowerShell encoded command | T1059.001 | Surface encoded or obfuscated PowerShell execution requiring analyst validation |
| Windows scheduled-task creation | T1053.005 | Identify task creation patterns that may represent persistence or administrative automation |
| New local administrator membership | T1098 / T1069 context | Flag privileged group changes for authorization and identity-risk review |

ATT&CK mappings describe behavioral context; they do **not** prove malicious activity by themselves.

## Repository structure

```text
.
├── README.md
├── rules/
│   ├── powershell_encoded_command.yml
│   ├── scheduled_task_creation.yml
│   └── local_admin_membership.yml
├── docs/
│   └── validation-playbook.md
└── tests/
    └── test_rule_metadata.py
```

## Engineering standards

Every detection in this repository should include:

- A clear title and unique identifier
- Log source / telemetry requirement
- Focused detection condition
- ATT&CK tags where appropriate
- False-positive considerations
- Severity level
- Triage and validation guidance
- Synthetic examples or metadata validation

## Detection quality principles

**Precision over noise.** A detection that fires constantly but provides little investigative value is not mature.

**Telemetry first.** A rule is only useful when the required events and fields are reliably collected.

**Behavior over tool names.** Prefer observable activity patterns where practical rather than hard-coding a single offensive tool.

**Validation before deployment.** Test expected positive and negative cases before claiming a detection works.

**Document assumptions.** Analysts should know what a signal can and cannot establish.

## Analyst triage model

When a rule alerts, validate:

1. User / service-account context
2. Parent and child process relationships
3. Command line or changed object
4. Host criticality and exposure
5. Related authentication activity
6. Network connections or follow-on behavior
7. Change / deployment authorization
8. Historical baseline for the user and asset

## Portfolio value

This lab demonstrates capability in:

- Detection Engineering
- Microsoft / Windows telemetry concepts
- SIEM content development
- MITRE ATT&CK mapping
- Incident triage
- False-positive analysis
- Rule quality assurance
- Security engineering documentation

## Safety and scope

All examples are designed for **defensive detection engineering, controlled laboratory validation, and professional education**. The repository does not contain real credentials, production telemetry, confidential employer/client data, or instructions for targeting third-party systems.

## Roadmap

- Add process-injection telemetry examples
- Add suspicious service creation detection
- Add credential-access behavioral detections
- Add lateral-movement detections
- Add cloud / identity Sigma-compatible analytics
- Add a lightweight synthetic event evaluator
- Add CI metadata validation for all rules

> **A good detection is not just a query. It is a documented hypothesis with known telemetry, expected behavior, validation evidence, and a clear analyst decision path.**
