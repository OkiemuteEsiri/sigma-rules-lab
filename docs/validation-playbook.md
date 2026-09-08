# Detection Validation Playbook

## Purpose

A detection is not production-ready merely because its query syntax is valid. This playbook defines a small, repeatable quality process for validating security analytics before deployment.

## Validation questions

For every rule, document:

1. **Threat hypothesis** — what behavior is the rule intended to surface?
2. **Telemetry dependency** — which event source, field names and collection controls are required?
3. **Positive case** — what known benign lab event should trigger the rule?
4. **Negative case** — what similar but acceptable activity should not trigger where practical?
5. **False positives** — which legitimate business workflows are likely to match?
6. **Triage context** — what additional evidence should an analyst gather?
7. **Severity rationale** — why is the alert level appropriate?
8. **ATT&CK mapping** — which technique provides behavioral context?
9. **Tuning decision** — what exclusions can be safely applied without suppressing meaningful activity?
10. **Retest** — does the rule still trigger after changes?

## Example: encoded PowerShell

### Hypothesis
Encoded PowerShell can be used to obscure command content. It is also used by legitimate administrative tooling, so the signal requires context rather than automatic incident declaration.

### Required telemetry
Process creation data should include at least:

- process image
- full command line
- parent process
- user identity
- hostname
- timestamp

### Analyst validation
Review:

- whether the command originated from approved management tooling
- parent/child process relationships
- user privilege level
- endpoint criticality
- script or command provenance where available
- related network connections
- adjacent authentication events
- whether similar activity is common for the same host/user

### Tuning principle
Prefer narrow, evidence-based exceptions, such as a known management process plus a controlled execution path. Avoid broad exclusions for entire user groups or PowerShell itself.

## Rule maturity model

| Stage | Definition |
|---|---|
| Draft | Hypothesis and initial logic exist |
| Tested | Synthetic positive/negative validation completed |
| Tuned | Known benign patterns reviewed and documented |
| Operational | Telemetry quality and analyst workflow confirmed |
| Reviewed | Performance and false-positive rate reassessed periodically |

## Documentation standard

Detection changes should explain **why** logic changed, not only what changed. This helps reviewers understand whether a modification improves precision, recall, telemetry compatibility or analyst usability.
