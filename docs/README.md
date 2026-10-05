# Security automation documentation

This documentation is for the people deploying, operating and maintaining the security CSV to Jira workflow. It describes the implemented system and its limits; it does not certify an AWS deployment or authorize production writes.

| Reader or task | Start here |
| --- | --- |
| First installation, prerequisites and staged activation | [Complete step-by-step setup guide](SETUP.md) |
| Project overview and local checks | [Repository README](../README.md) |
| Architecture, identities and trust boundaries | [Architecture](ARCHITECTURE.md) |
| Private environment and deployment settings | [Configuration](CONFIGURATION.md) |
| Routine imports, evidence and recovery | [Operating guide](../OPERATIONS.md) |
| Developer remediation and Jira ticket conventions | [Ticket guide](TICKET_GUIDE.md) |
| GitHub publication and contribution checks | [GitHub guide](GITHUB.md) |
| Remaining risks and recommended improvements | [Deep review](DEEP_REVIEW.md) |
| Tested scope and release evidence | [Implementation status](../IMPLEMENTATION_STATUS.md) |
| Reporting a vulnerability | [Security policy](../SECURITY.md) |

Keep real reports, populated settings, approval files and exports outside tracked documentation. Examples are synthetic. Record environment-specific decisions in your private operational system, not by editing the blank public settings templates.
