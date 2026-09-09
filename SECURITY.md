# Security Policy

## Reporting Security Issues

Security-sensitive findings affecting this repository should be reported privately.

Do not disclose suspected vulnerabilities, exposed credentials, or sensitive configuration through a public GitHub issue.

Use GitHub Private Vulnerability Reporting when available.

## Secrets

API keys, access tokens, credentials and other secrets must never be committed to the repository.

Future secrets required by automation will be stored using GitHub Actions Secrets or an equivalent protected secret store.

## Threat Intelligence Safety

This repository processes security intelligence metadata and potentially malicious indicators.

The project must not contain:

- malware samples
- executable payloads
- credential material
- private keys
- raw API secrets
- unauthorized confidential data

Human-readable threat indicators should be defanged where appropriate to reduce accidental interaction.

## Scope

Security reports may include issues affecting:

- repository source code
- automation workflows
- generated intelligence artifacts
- dependency configuration
- publication logic
- accidental exposure of secrets

Third-party services and upstream intelligence providers remain outside the direct security scope of this repository.