# jumpcloud-mcp

MCP server for JumpCloud APIs with:
- Full API surface access through JumpCloud OpenAPI specs
- Multi-user token management persisted in Vault
- Non-secret runtime configuration persisted in Postgres
- Mutating-tool guard using `MCP_ADMIN_AUTH_KEY`
- Stdio and HTTP transports

## Solution Summary

This repository is adapted from `skeleton-mcp` into a JumpCloud-specific implementation.

Key design requirements implemented:
- Secrets are persisted in Vault only.
- Configuration is persisted in Postgres only.
- User tokens are multi-user by design (`app/users/:userId/jumpcloud/tokens`).
- Mutation tools can require `authorizationKey` when `MCP_ADMIN_AUTH_KEY` is configured.
- Full JumpCloud API coverage is supported via OpenAPI-driven discovery and execution.

## JumpCloud Coverage Model

`jumpcloud-mcp` supports complete endpoint coverage by loading these OpenAPI specs at runtime:
- Console API: `https://docs.jumpcloud.com/new/console/index.yaml`
- Directory Insights API: `https://docs.jumpcloud.com/new/api/insights/directory/index.yaml`

Coverage is exposed by:
- `jumpcloud_openapi_discovery` for endpoint/operation discovery
- `jumpcloud_operation_invoke` for operationId-driven execution
- `jumpcloud_api_request` for explicit method/path execution

## Endpoint Inventory Artifact

This repository can generate a deterministic endpoint inventory artifact for diffing API coverage changes:

- JSON inventory: `docs/openapi-endpoint-inventory.json`
- Markdown summary: `docs/openapi-endpoint-inventory.md`

Commands:

```bash
npm run inventory:generate
npm run inventory:check
```

`inventory:check` regenerates the artifact and fails if committed files are out of date.

CI workflow:
- `.github/workflows/openapi-inventory-check.yml` runs `npm run inventory:check` on push and pull requests.

## Architecture

Runtime flow:
1. `src/index.js` starts stdio MCP mode.
2. `src/http/index.js` starts HTTP MCP mode.
3. `src/config/env.js` validates runtime configuration.
4. `src/services/vault.js` manages persistent secrets.
5. `src/services/configStore.js` manages persistent config in Postgres.
6. `src/services/targetService.js` loads OpenAPI and executes JumpCloud calls.
7. `src/mcp/server.js` registers tools, auth checks, and responses.

Persistence model:
- Secrets: Vault KV (`secret/data/<app>/users/<user>/jumpcloud/tokens`)
- Config: Postgres table (`<app>_config`) scoped by `user_id`

## Setup

1. Install dependencies:

```bash
npm install
```

2. Copy and edit environment:

```bash
cp .env.example .env
```

3. Start local infra:

```bash
docker compose up -d postgres vault
```

4. Start server:

```bash
npm run start:stdio
# or
npm run start:http
```

## External Services Mode

Use `docker-compose.external.yml` when Vault and Postgres are managed externally.

Required env vars in this mode include:
- `POSTGRES_HOST`
- `VAULT_ADDR`

Start app-only stack:

```bash
docker compose -f docker-compose.external.yml up -d
```

## MCP Tool Catalog

All tools return JSON in text content with shape:

```json
{
  "ok": true,
  "status": 200,
  "data": {}
}
```

Errors return `isError=true` and shape:

```json
{
  "ok": false,
  "status": 401,
  "error": "Unauthorized: invalid authorizationKey for mutating API request"
}
```

### jumpcloud_query_suggestion

- Use when: you need planning guidance, schema guidance, and recommended tool sequence.
- Do not use when: you already know the exact tool and operation.
- Access type: read-only.
- Risk: low.
- Required permissions: none.
- Environment behavior: reads active OpenAPI operation metadata from loaded specs.
- Parameters:
  - `intent` string optional
  - `domain` enum optional: `console|directory-insights`
  - `method` string optional
  - `path` string optional
  - `includeToolSchemas` boolean optional
- Response shape:
  - `data.summary`
  - `data.recommendedOrder`
  - `data.suggestedOperations`
  - `data.safetyChecks`
  - `data.toolSchemas` (unless disabled)
- Common failures: OpenAPI fetch/parse errors.
- Recommended prereq: `jumpcloud_connection_info`.
- Follow-up tools: `jumpcloud_openapi_discovery`, `jumpcloud_operation_invoke`, `jumpcloud_api_request`.
- Example:

```json
{
  "name": "jumpcloud_query_suggestion",
  "arguments": {
    "intent": "list users then update one user",
    "domain": "console"
  }
}
```

### jumpcloud_openapi_discovery

- Use when: you need schema discovery for operation IDs, methods, paths, tags, and domains.
- Do not use when: you are ready to execute and already know the operation.
- Access type: read-only.
- Risk: low.
- Required permissions: none.
- Environment behavior: returns operation metadata from OpenAPI cache.
- Parameters:
  - `domain` enum optional: `console|directory-insights`
  - `search` string optional
  - `limit` int optional (max 500)
- Response shape:
  - `data.endpoints[]`
  - `data.count`
  - `data.totalDiscovered`
- Common failures: OpenAPI fetch/parse errors.
- Recommended prereq: `jumpcloud_connection_info`.
- Follow-up tools: `jumpcloud_operation_invoke`, `jumpcloud_api_request`.
- Example:

```json
{
  "name": "jumpcloud_openapi_discovery",
  "arguments": {
    "domain": "console",
    "search": "systemusers",
    "limit": 20
  }
}
```

### jumpcloud_operation_invoke

- Use when: you have an operationId and want strict OpenAPI-based invocation.
- Do not use when: you only have raw method/path; use `jumpcloud_api_request`.
- Access type: read-only or mutating (depends on operation method).
- Risk: variable.
- Required permissions:
  - Active user token in Vault.
  - `authorizationKey` required for mutating operations if `MCP_ADMIN_AUTH_KEY` is set.
- Environment behavior: operation domain inferred from OpenAPI metadata.
- Parameters:
  - `userId` optional (defaults to `MCP_CONFIG_DEFAULT_USER_ID`)
  - `tokenId` optional (defaults to active token)
  - `operationId` required
  - `pathParams` optional record
  - `query` optional record
  - `body` optional JSON
  - `headers` optional record
  - `authorizationKey` optional unless gated mutation
- Response shape:
  - `data.domain`, `data.method`, `data.path`, `data.status`, `data.data`
- Common failures:
  - Unknown operationId
  - Missing required path parameter
  - Missing/inactive token
  - JumpCloud API errors
- Recommended prereq: `jumpcloud_openapi_discovery`.
- Follow-up tools: `jumpcloud_api_request` for edge cases.
- Safety warning: high-impact on production identity/device state for mutating operations.
- Example:

```json
{
  "name": "jumpcloud_operation_invoke",
  "arguments": {
    "userId": "team-a",
    "operationId": "systemusers_list",
    "query": {
      "limit": 10
    }
  }
}
```

### jumpcloud_api_request

- Use when: you need explicit HTTP method/path execution with full API coverage.
- Do not use when: planning/discovery only.
- Access type: read-only or mutating.
- Risk: variable.
- Required permissions:
  - Active user token in Vault.
  - `authorizationKey` for mutating methods (`POST|PUT|PATCH|DELETE`) when admin key is configured.
- Environment behavior: routes via `domain` to Console or Directory Insights base URL.
- Parameters:
  - `userId` optional
  - `tokenId` optional
  - `domain` optional: `console|directory-insights`
  - `method` required
  - `path` required
  - `query` optional object
  - `body` optional JSON
  - `headers` optional object
  - `authorizationKey` optional unless gated mutation
- Response shape:
  - `data.domain`, `data.method`, `data.path`, `data.status`, `data.data`
- Common failures: token missing, auth errors, timeout, invalid path, JumpCloud errors.
- Recommended prereq: `jumpcloud_openapi_discovery`.
- Follow-up tools: `jumpcloud_query_suggestion` for next step guidance.
- Safety warning: mutating calls can alter production directory state.
- Example:

```json
{
  "name": "jumpcloud_api_request",
  "arguments": {
    "userId": "default",
    "domain": "console",
    "method": "GET",
    "path": "/api/systemusers"
  }
}
```

### jumpcloud_user_token_list

- Use when: checking per-user token metadata and active selection.
- Do not use when: creating/updating/deleting tokens.
- Access type: read-only.
- Risk: medium.
- Required permissions: none.
- Environment behavior: reads Vault token document for selected user.
- Parameters:
  - `userId` optional
  - `includeSensitive` optional (actual values remain redacted unless sensitive output is enabled)
- Response shape:
  - `data.userId`, `data.activeTokenId`, `data.tokens`
- Common failures: Vault connectivity/read issues.
- Recommended prereq: `jumpcloud_scope_info`.
- Follow-up tools: `jumpcloud_user_token_upsert`, `jumpcloud_user_token_set_active`, `jumpcloud_user_token_delete`.

### jumpcloud_user_token_upsert

- Use when: creating/updating a user-scoped JumpCloud token in Vault.
- Do not use when: read-only inspection.
- Access type: mutating.
- Risk: high.
- Required permissions:
  - `authorizationKey` when `MCP_ADMIN_AUTH_KEY` is configured.
- Environment behavior: writes to user Vault path and may initialize active token.
- Parameters:
  - `userId` optional
  - `tokenId` required
  - `value` required
  - `tokenType` optional: `apiKey|bearer`
  - `headerName` optional
  - `description` optional
  - `authorizationKey` optional unless gated
- Response shape:
  - `data.userId`, `data.tokenId`, `data.activeTokenId`
- Common failures: Vault write failure, invalid payload.
- Recommended prereq: `jumpcloud_scope_info`.
- Follow-up tools: `jumpcloud_user_token_set_active`, `jumpcloud_api_request`.

### jumpcloud_user_token_set_active

- Use when: switching active token for a user.
- Do not use when: creating token material.
- Access type: mutating.
- Risk: medium.
- Required permissions: `authorizationKey` when admin key is configured.
- Environment behavior: updates active token pointer in Vault document.
- Parameters:
  - `userId` optional
  - `tokenId` required
  - `authorizationKey` optional unless gated
- Response shape: `data.userId`, `data.activeTokenId`
- Common failures: unknown tokenId, Vault write failure.

### jumpcloud_user_token_delete

- Use when: removing obsolete token entries.
- Do not use when: only deactivation is needed.
- Access type: mutating.
- Risk: high.
- Required permissions: `authorizationKey` when admin key is configured.
- Environment behavior: deletes token and may reselect active token.
- Parameters:
  - `userId` optional
  - `tokenId` required
  - `authorizationKey` optional unless gated
- Response shape: `data.userId`, `data.activeTokenId`, `data.remainingTokenCount`
- Common failures: Vault write failure.
- Safety warning: destructive operation.

### jumpcloud_config_list / jumpcloud_config_get

- Use when: retrieving non-secret per-user Postgres config.
- Do not use when: storing secrets.
- Access type: read-only.
- Risk: low.
- Required permissions: none.
- Environment behavior: reads `<app>_config` table by `user_id`.

### jumpcloud_config_set / jumpcloud_config_delete

- Use when: writing/deleting non-secret per-user configuration.
- Do not use when: storing token values or other sensitive secrets.
- Access type: mutating.
- Risk: medium/high.
- Required permissions: `authorizationKey` when admin key is configured.
- Environment behavior: writes/deletes rows in Postgres config table.
- Safety warning (`jumpcloud_config_delete`): destructive operation.

### jumpcloud_connection_info / jumpcloud_scope_info / jumpcloud_health_check

- `jumpcloud_connection_info`: read-only server/runtime metadata.
- `jumpcloud_scope_info`: read-only effective app/user scope resolver.
- `jumpcloud_health_check`: read-only API connectivity/auth check using active user token.

## HTTP Auth for MCP Endpoint

The MCP HTTP endpoint supports:
- Vault token index auth (`MCP_HTTP_AUTH_MODE=token`)
- OAuth2 introspection auth (`MCP_HTTP_AUTH_MODE=oauth2`)
- Dual acceptance (`MCP_HTTP_AUTH_MODE=both`)

## Tests

Run:

```bash
npm test
```

Highlights:
- OpenAPI discovery and operation invocation tests
- Multi-user token behavior tests
- Admin auth gating tests for mutating tools
- HTTP integration and Vault-related tests

## License

MIT. See `LICENSE`.
