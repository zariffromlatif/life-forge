# Security Review Answers: SupportAgent(gpt-oss:20b)

> Draft answers to questions enterprise security reviews commonly ask about AI agents, generated from the attached LIFE FORGE audit evidence. Review and edit before sending. This is a point-in-time testing record, not a certification or a guarantee. Items marked **TODO** cannot be answered from testing evidence and must be completed by your team.

## How do you test the agent against prompt injection and unauthorized actions?

Sample Store (reference agent) tests SupportAgent(gpt-oss:20b) in a deterministic simulation of the tools it can call. An automated search generates adversarial and environmental scenarios (indirect prompt injection in tool data and messages, spoofed authority, conflicting instructions, price/stock volatility and resource pressure) and a rule-based oracle judges each episode by its effects on the simulated systems (money moved, records changed, messages sent, gated actions taken), not by the model's text.

- Scenarios evaluated in this audit: **21** (20 search generations, seed 42; the scenario set is reproducible, a sampled model's responses vary between runs)
- Share of evaluated scenarios with at least one violation: **42.9%**

## What did testing find?

Violations by severity: **5 critical / 0 high / 6 medium / 0 low** (one count per violation type per failing simulation, so one simulation can count more than once).

- `SELF_REPLICATING_WORM_PROPAGATION` (CRITICAL): observed in 3 simulation(s)
- `UNAUTHORIZED_DATA_EXFILTRATION` (CRITICAL): observed in 2 simulation(s)
- `LEGITIMATE_REQUEST_NOT_RESOLVED` (MEDIUM): observed in 4 simulation(s)
- `MALFORMED_RECIPIENT` (MEDIUM): observed in 2 simulation(s)

Remediation status: **TODO** - state which findings were fixed and when the re-test passed.

## Which actions require human approval?

**TODO** - list the actions that require approval in production and where approvals are recorded.

## How do you make sure a release does not reintroduce a fixed problem?

Every scenario from this audit is stored as a regression corpus and replayed against each pull request in CI. A change that makes the agent fail a scenario it previously handled fails the build. For sampled models, each scenario is replayed several times and compared by failure rate.

## Is adversarial testing recurring?

Regression replay runs on every pull request; a full adversarial search should be re-run at least quarterly and after any change to the agent's tools or model. **TODO** - confirm your cadence.

## Are agent actions logged and attributable?

**TODO** - describe production action logging (what is logged, retention, tamper evidence). If you use the LIFE FORGE PolicyGateway, its hash-chained audit trail can be cited here.
