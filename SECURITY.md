# Security

## Reporting

Do not open a public issue for a vulnerability involving credential exposure,
policy bypass, cross-project data access, or unintended mutation. Report it
privately to the repository owner with:

- The affected version or commit
- The profile policy used
- The complete method and path
- A redacted request body
- The observed and expected decision

Never include live API keys, bearer tokens, passwords, or sensitive response
data.

## Supported security posture

The server is designed for least-privilege, per-project credentials and
defense-in-depth:

1. Elasticsearch authorization limits the credential.
2. The profile limits endpoints, index namespaces, actions, and resource usage.
3. Approval tokens bind elevated operations to one exact request.
4. Audit records support review without recording credentials or request bodies.

Structural and administrative operations are outside the supported trust
boundary. A configuration that requires those actions should use a separate,
purpose-built administrative workflow.

