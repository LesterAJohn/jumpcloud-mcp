---
mode: agent
tools: ["codebase", "editFiles", "search", "testFailure"]
description: "Extend jumpcloud-mcp with additional JumpCloud-focused tools or runtime behavior."
---

Implement the requested enhancement while preserving these rules:
- Secrets remain in Vault.
- Configuration remains in Postgres.
- Multi-user token scope remains enforced.
- Mutating tools require authorization key when admin key is configured.
- Keep compatibility with external Vault/Postgres services via app-only compose startup.

Required output quality:
1. Update implementation in `src/*`.
2. Add/adjust tests in `tests/*`.
3. Update README so tool behavior and examples match code.
4. Run and report `npm test`.
