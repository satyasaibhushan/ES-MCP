# ES MCP

A configuration-controlled MCP server for Elasticsearch. It places deterministic
policy enforcement between an MCP client and Elasticsearch:

- Named profiles isolate projects and environments.
- Profiles can own lazy, reusable SSH tunnels with dynamic local ports.
- Both the HTTP method and endpoint are classified. `GET` and `POST` searches
  are reads; a `POST` update is a write.
- Every index expression is checked against its profile before a request leaves
  the process.
- Expensive reads and document writes can require exact, single-use approval.
- Structural, cluster, security, and unknown endpoints are hard-denied.
- Request size, response size, hit count, aggregation size, pagination, scripts,
  wildcard expansion, and execution time are bounded.
- Decisions and executions are written to an append-only local audit log.

This is not a generic Elasticsearch proxy.

## Security boundary

The server does not trust the model or caller to enforce policy. A request passes
through:

```text
MCP tool
  -> method/path/body classifier
  -> project and index policy
  -> request limits
  -> optional exact-request approval
  -> optional managed SSH tunnel
  -> bounded HTTP client
  -> Elasticsearch
```

Where possible, use one least-privilege Elasticsearch API key per profile. The
API key's native role should mirror the profile's index patterns. Application
policy is a second layer, not a replacement for Elasticsearch authorization.

Do not use a cluster administrator or `superuser` credential.

Private VPC domains may instead accept unsigned requests based on network
position. These profiles must declare `auth: {none: true}` explicitly and
should use the managed SSH tunnel. In that mode, the MCP policy is the primary
per-index application boundary because the cluster does not receive a profile
identity.

## Supported endpoints

Automatically allowed when the profile permits the target:

| Operation | Methods | Path |
| --- | --- | --- |
| Search | `GET`, `POST` | `/{index}/_search` |
| Count | `GET`, `POST` | `/{index}/_count` |
| Field capabilities | `GET`, `POST` | `/{index}/_field_caps` |
| Validate query | `GET`, `POST` | `/{index}/_validate/query` |
| Mapping | `GET` | `/{index}/_mapping` |
| Resolve index | `GET`, `POST` | `/_resolve/index/{index}` |
| Multi-get | `GET`, `POST` | `/{index}/_mget` |
| Get document/source | `GET`, `HEAD` | `/{index}/_doc/{id}`, `/{index}/_source/{id}` |

Document operations that may be configured as approval-required:

| Operation | Methods | Path |
| --- | --- | --- |
| Create | `PUT`, `POST` | `/{index}/_create/{id}` |
| Index | `PUT`, `POST` | `/{index}/_doc/{id}` |
| Index with generated ID | `POST` | `/{index}/_doc` |
| Update | `POST` | `/{index}/_update/{id}` |
| Delete document | `DELETE` | `/{index}/_doc/{id}` |

Document operations require an exact index name. Bulk, update-by-query,
delete-by-query, reindex, mappings changes, settings changes, index deletion,
cluster administration, security administration, hidden indices, remote
clusters, and unknown endpoints are denied.

## Action tiers

| Tier | Configuration key | Examples | Default |
| --- | --- | --- | --- |
| 0 | `discovery` | Sanitized profile discovery | `allow` |
| 1 | `read` | Bounded search and metadata | `allow` |
| 2 | `expensive_read` | Scripts, runtime mappings, profiling, exact total hits | `deny` |
| 3 | `document_write` | Create, index, update, delete by ID | `deny` |
| 4 | `structural_write` | Bulk, reindex, mappings, settings, index deletion | hard deny |
| 5 | `admin` | Cluster, nodes, snapshots, users, roles, API keys | hard deny |

Tier 2 accepts `allow`, `approve`, or `deny`. Tier 3 accepts `approve` or
`deny`; document writes cannot bypass approval. Tier 4 and 5 cannot be enabled
in this version.

Scripts and runtime mappings also require `limits.allow_scripts: true`. This is
an independent safety switch, so enabling the expensive-read tier alone does
not enable scripts.

## Installation

Requirements:

- Python 3.10+
- [`uv`](https://docs.astral.sh/uv/) or another Python package installer
- An Elasticsearch API key with a least-privilege role
- SSH access when using private, tunnelled endpoints

Install and run the tests:

```bash
uv sync --extra dev
uv run pytest
```

Copy the examples outside the repository:

```bash
mkdir -p ~/.es-access
cp examples/profiles.yaml ~/.es-access/profiles.yaml
cp examples/secrets.env.example ~/.es-access/secrets.env
chmod 600 ~/.es-access/profiles.yaml ~/.es-access/secrets.env
```

Edit both files, then validate without connecting to Elasticsearch:

```bash
uv run es-mcp --check-config
```

To open every configured tunnel and run a sanitized endpoint/version check:

```bash
uv run es-mcp --check-connections
```

The default paths are:

- Profiles: `~/.es-access/profiles.yaml`
- Secrets: `~/.es-access/secrets.env`
- Audit logs: `~/.es-access/audit/audit-YYYY-MM-DD.jsonl`

Override them with `ES_MCP_PROFILES`, `ES_MCP_SECRETS`, and
`ES_MCP_AUDIT_DIR`.

## MCP client configuration

Configure the client to start the server over stdio:

```json
{
  "mcpServers": {
    "elasticsearch": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/ES-MCP",
        "run",
        "es-mcp"
      ],
      "env": {
        "ES_MCP_PROFILES": "/absolute/path/to/profiles.yaml"
      }
    }
  }
}
```

The server exposes:

- `es_list_profiles`
- `es_describe_profile`
- `es_check_connection`
- `es_request`
- `es_plan_request`
- `es_execute_approved_request`

An ordinary read request:

```json
{
  "profile": "payments_uat",
  "method": "POST",
  "path": "/payments-logs-2026*/_search",
  "body": {
    "query": {
      "match": {
        "message": "timeout"
      }
    },
    "size": 20
  }
}
```

For an approval-required operation, call `es_plan_request`. After the user
approves the displayed method, path, operation, targets, and request hash, pass
the unchanged request and returned token to `es_execute_approved_request`.
Tokens expire after five minutes and are consumed before execution, including
when execution fails.

## Authentication

Configure exactly one authentication mode:

```yaml
auth:
  api_key_env: PROJECT_ES_API_KEY
```

```yaml
auth:
  bearer_token_env: PROJECT_ES_BEARER_TOKEN
```

```yaml
auth:
  username: reader
  password_env: PROJECT_ES_PASSWORD
```

For a network-position-authorized private endpoint:

```yaml
auth:
  none: true
```

No-auth is accepted only with managed SSH enabled or for a loopback URL. It
never emits an `Authorization` header.

## Managed SSH tunnels

Each SSH-enabled profile owns one tunnel:

```yaml
url: https://es-uat.example.test

ssh:
  enabled: true
  host: ssh.example.test
  port: 22
  user: limited-user
  key_path: ~/.ssh/id_rsa
  key_passphrase_env: SSH_KEY_PASSPHRASE
  known_hosts_path: ~/.ssh/known_hosts
  verify_host_key: true
  local_host: 127.0.0.1
  local_port:
  remote_host: es-uat.example.test
  remote_port: 443
  keepalive_seconds: 30
```

The tunnel starts on first use, chooses a dynamic loopback port when
`local_port` is empty, stays alive across requests, restarts after failure, and
closes with the MCP process.

If the configured private key is encrypted and its passphrase environment
variable is unset, ES-MCP falls back to keys already loaded in the SSH agent.
This avoids copying an existing key passphrase into the ES-MCP secrets file.

The profile URL remains the real remote URL. The HTTP transport connects its
TCP socket to the tunnel while retaining the URL hostname for TLS SNI,
certificate validation, and the HTTP `Host` header. This permits
`tls.verify: true`; use `tls.ca_cert` for a private CA rather than disabling
verification.

SSH gateway host keys are checked against `~/.ssh/known_hosts` by default.
`verify_host_key: false` exists for disposable local testing and should not be
used for shared environments.

## Native Elasticsearch role

The profile should be backed by a key whose role is at least as restrictive.
For a read-only profile:

```json
{
  "cluster": [],
  "indices": [
    {
      "names": [
        "payments-logs-*",
        "payments-metrics-*",
        "payments-events"
      ],
      "privileges": [
        "read",
        "view_index_metadata"
      ],
      "allow_restricted_indices": false
    }
  ]
}
```

Add only the minimum native document privileges needed when writes are enabled.
Elasticsearch native privileges may group several document operations together;
the server's per-operation allow-list remains the narrower application layer.

If projects share an index, index patterns are insufficient isolation. Prefer
separate indices. Otherwise use Elasticsearch document- and field-level
security where the deployment supports them.

For unsigned VPC profiles, a native per-profile role is unavailable. Bind the
tunnel only to loopback, keep the SSH gateway restricted, and treat local
processes on the machine as part of the trust boundary.

## Configuration rules

- Read permissions must contain at least one exact index or trailing-wildcard
  namespace such as `payments-logs-*`.
- Global `*`, `_all`, comma-separated expressions, exclusion expressions,
  remote cluster syntax, `?`, character classes, and non-trailing wildcards are
  rejected during configuration or request validation.
- Secrets are never returned by profile discovery tools.
- Missing authentication is rejected; anonymous access must be explicit.
- URLs cannot contain embedded credentials.
- TLS verification defaults to enabled. Turning it off should be limited to
  disposable local environments.
- Redirects are not followed.
- SSH remote host must match the profile URL host.
- Managed tunnels bind only to `127.0.0.1`; dynamic ports are recommended.
- Multi-get bodies cannot override `_index`.
- Cross-index terms lookup is rejected.

## Development

```bash
uv run pytest -q
uv run python -m compileall -q src tests
```

The tests use mocked HTTP transports and do not require a running cluster.
