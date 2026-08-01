# JumpCloud Capability Onboarding

Use this checklist when extending `jumpcloud-mcp`.

## 1. Capability Definition

- Identify target JumpCloud domain (`console` or `directory-insights`).
- Classify operations into read-only vs mutating.
- Define user/token scoping requirements.
- Define expected safety constraints and fallback behavior.

## 2. Persistence Boundaries

- Keep secrets in Vault only.
- Keep non-secret config in Postgres only.
- Do not duplicate sensitive token values in Postgres.

## 3. Tool Surface

- Add discovery metadata via `jumpcloud_openapi_discovery` and `jumpcloud_query_suggestion` behavior.
- Add dedicated tools only where they add safety or reduce invocation complexity.
- Gate mutating tools behind `authorizationKey` when `MCP_ADMIN_AUTH_KEY` is configured.

## 4. Runtime + Env

- Add validated env vars in `src/config/env.js`.
- Preserve stdio/http/both transport behavior.
- Preserve HTTP auth behavior and limits.

## 5. Tests

- Add tool-level tests for success and failure paths.
- Add mutation auth tests.
- Add multi-user token tests.
- Update integration tests if tool names/contracts change.

## 6. Docs

- Update README tool catalog.
- Document when each tool should and should not be used.
- Document permissions, risks, and examples.
- Keep environment variable docs in sync with code.
- Preserve app-only compose path documentation for external service deployments (`docker-compose.external.yml`).