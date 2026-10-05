# Security policy

Do not publish credentials, real finding exports, private environment files, verification approvals or exploit details in public issues or pull requests. Use GitHub private vulnerability reporting if it is enabled for this repository; otherwise arrange an approved private channel with the repository owner. This project does not currently promise a response SLA or a configured public contact address.

Supported maintenance scope is the current reviewed branch and Python 3.12 runtime. No hosted production deployment is implied by repository availability. Report the affected revision, configuration assumptions, reproducible synthetic input, impact and proposed mitigation without exposing customer data.

The repository preflight checks tracked files, populated settings templates and recognizable credential patterns. It is not a complete secret scanner, a full-history scan or a substitute for GitHub secret protection and an independent approved scanner. If a real secret is committed, revoke/rotate it first; deleting the current file does not erase history or copies.

Runtime credentials must remain in Secrets Manager and AWS IAM/SSO. Never commit populated configuration, bypass the clean-attachment checks or weaken signed identity verification to recover a stalled import. Use reviewed repair/restoration operations and preserve the audit evidence.
