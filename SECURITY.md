# Security Policy

## Supported Versions

LIFE FORGE actively supports security fixes on the latest minor version release:

| Version | Supported          |
| :---    | :---               |
| 0.2.x   | [OK] Yes           |
| < 0.2.0 | [FAIL] End of Life |

## Responsible Vulnerability Disclosure

LIFE FORGE is an adversarial simulation and red-teaming platform designed to discover failure modes and vulnerabilities in autonomous AI agents. While the tool generates adversarial prompts and mock exploit scenarios within a sandboxed environment, we take the security of the framework itself seriously.

If you believe you have discovered a security vulnerability in the LIFE FORGE codebase (such as sandbox escape, arbitrary code execution via mutators, or unsafe deserialization):

1. **Do not create a public GitHub issue.**
2. Send an email to the project maintainer:
   - Email: `102543743+zariffromlatif@users.noreply.github.com`
   - Subject: `[SECURITY] LIFE FORGE Vulnerability Report`
3. Include in your report:
   - A description of the vulnerability and its potential impact.
   - Minimal reproduction steps or a proof-of-concept script.
   - Any relevant logs, system configuration, or environmental conditions.

## Response SLA

- **Initial Acknowledgment**: Within 48 hours of receipt.
- **Triage & Validation**: Within 5 business days.
- **Remediation & Patch**: Target resolution within 14 days, followed by coordinated public disclosure.

## Sandboxing Notice

LIFE FORGE executes simulated agent environments deterministically in memory. When connecting live LLMs or custom external tools to the flight simulator, ensure external network access and privileged system commands are properly isolated according to your organization's security policies.
