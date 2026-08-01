import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { redactObject } from "../services/security.js";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function normalizeMethod(method) {
  return String(method ?? "GET").trim().toUpperCase();
}

function normalizePath(path) {
  const raw = String(path ?? "").trim();
  if (!raw) {
    return "/";
  }

  return raw.startsWith("/") ? raw : `/${raw}`;
}

function asText(value) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(value, null, 2)
      }
    ]
  };
}

function classifyToolError(error) {
  const status = Number(error?.status ?? error?.statusCode ?? 500);
  const payload = {
    ok: false,
    status: Number.isFinite(status) ? status : 500,
    error: error instanceof Error ? error.message : String(error)
  };

  if (error?.response !== undefined) {
    payload.details = error.response;
  }

  return payload;
}

function withErrorHandling(handler) {
  return async (args) => {
    try {
      return asText(await handler(args));
    } catch (error) {
      return {
        ...asText(classifyToolError(error)),
        isError: true
      };
    }
  };
}

function requiresAdminKey(adminAuthKey, method) {
  return Boolean(adminAuthKey) && MUTATING_METHODS.has(normalizeMethod(method));
}

function toBoolean(value, fallback) {
  if (value === undefined || value === null) {
    return fallback;
  }

  if (typeof value === "boolean") {
    return value;
  }

  const normalized = String(value).trim().toLowerCase();
  if (normalized === "true") {
    return true;
  }
  if (normalized === "false") {
    return false;
  }

  return fallback;
}

function toStringArray(value, { upper = false } = {}) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((item) => String(item ?? "").trim())
    .filter(Boolean)
    .map((item) => (upper ? item.toUpperCase() : item));
}

function buildToolSchemas({ adminAuthConfigured }) {
  return [
    {
      name: "jumpcloud_query_suggestion",
      category: "read-only",
      risk: "low",
      whenToUse: "Use for workflow planning, operation discovery, and recommended safe call ordering.",
      whenNotToUse: "Do not use when you already know the exact tool/operation and parameters.",
      permissions: "No JumpCloud mutation required. No admin key required.",
      environmentBehavior: "Reads loaded OpenAPI metadata from JumpCloud Console + Directory Insights specs.",
      parameterNotes: "intent/domain/method/path are optional hints.",
      responseShape: "{ ok, status, data: { recommendedOrder, suggestedOperations, safetyChecks, toolSchemas } }",
      failureConditions: "Spec download or parsing failures.",
      prereqTools: ["jumpcloud_connection_info"],
      followUpTools: ["jumpcloud_openapi_discovery", "jumpcloud_operation_invoke", "jumpcloud_api_request"],
      examples: [
        {
          name: "jumpcloud_query_suggestion",
          arguments: {
            intent: "list users then update one user",
            domain: "console"
          }
        }
      ]
    },
    {
      name: "jumpcloud_openapi_discovery",
      category: "read-only",
      risk: "low",
      whenToUse: "Use to search all discovered JumpCloud operations from OpenAPI specs.",
      whenNotToUse: "Do not use as a substitute for executing an API call.",
      permissions: "No admin key required.",
      environmentBehavior: "Returns operation metadata from the currently loaded specs.",
      parameterNotes: "Supports optional domain, search text, and result limit.",
      responseShape: "{ ok, status, data: { endpoints[], count, totalDiscovered } }",
      failureConditions: "Spec retrieval errors.",
      prereqTools: ["jumpcloud_connection_info"],
      followUpTools: ["jumpcloud_operation_invoke", "jumpcloud_api_request"],
      examples: [
        {
          name: "jumpcloud_openapi_discovery",
          arguments: {
            search: "system users",
            domain: "console",
            limit: 20
          }
        }
      ]
    },
    {
      name: "jumpcloud_tenant_list",
      category: "read-only",
      risk: "low",
      whenToUse: "Use to discover configured tenants and optionally their scoped users.",
      whenNotToUse: "Do not use for token or config mutation workflows.",
      permissions: "No admin key required.",
      environmentBehavior: "Combines Postgres config scope discovery with Vault tenant token user discovery.",
      parameterNotes: "includeUsers=true returns users from Postgres and Vault per tenant.",
      responseShape: "{ ok, status, data: { tenants[], count } }",
      failureConditions: "Postgres or Vault metadata read failures.",
      prereqTools: ["jumpcloud_scope_info"],
      followUpTools: ["jumpcloud_tenant_scope_validate", "jumpcloud_tenant_bootstrap_defaults"],
      examples: [
        {
          name: "jumpcloud_tenant_list",
          arguments: {
            includeUsers: true
          }
        }
      ]
    },
    {
      name: "jumpcloud_tenant_scope_validate",
      category: "read-only",
      risk: "medium",
      whenToUse: "Use to validate a tenant/user scope has token and config readiness for API calls.",
      whenNotToUse: "Do not use as a replacement for real API health checks.",
      permissions: "No admin key required.",
      environmentBehavior: "Reads Vault token document and scoped Postgres config entries.",
      parameterNotes: "tenantId and userId default to configured defaults when omitted.",
      responseShape: "{ ok, status, data: { scope, checks, recommendations } }",
      failureConditions: "Vault access failures, Postgres access failures.",
      prereqTools: ["jumpcloud_scope_info"],
      followUpTools: ["jumpcloud_user_token_upsert", "jumpcloud_config_set", "jumpcloud_health_check"],
      examples: [
        {
          name: "jumpcloud_tenant_scope_validate",
          arguments: {
            tenantId: "acme",
            userId: "ops"
          }
        }
      ]
    },
    {
      name: "jumpcloud_tenant_bootstrap_defaults",
      category: "mutating",
      risk: "high",
      whenToUse: "Use to initialize baseline non-secret config defaults for a tenant/user scope.",
      whenNotToUse: "Do not use for token or secret storage; use Vault token tools for that.",
      permissions: "Requires authorizationKey when MCP_ADMIN_AUTH_KEY is configured.",
      environmentBehavior: "Writes scoped defaults in Postgres for tenant/user.",
      parameterNotes: "defaults is optional object merged with recommended baseline keys.",
      responseShape: "{ ok, status, data: { scope, appliedDefaults, records } }",
      failureConditions: "Postgres write failures.",
      prereqTools: ["jumpcloud_tenant_scope_validate"],
      followUpTools: ["jumpcloud_config_get", "jumpcloud_health_check"],
      safetyWarnings: "Mutating operation; verify tenantId/userId target before execution.",
      examples: [
        {
          name: "jumpcloud_tenant_bootstrap_defaults",
          arguments: {
            tenantId: "acme",
            userId: "ops",
            defaults: {
              "jumpcloud.defaultDomain": "console"
            },
            authorizationKey: "<admin-key-if-required>"
          }
        }
      ]
    },
    {
      name: "jumpcloud_tenant_policy_get",
      category: "read-only",
      risk: "medium",
      whenToUse: "Use to inspect effective tenant/user policy guardrails before operational calls.",
      whenNotToUse: "Do not use for policy mutation.",
      permissions: "No admin key required.",
      environmentBehavior: "Reads policy keys from scoped Postgres config.",
      parameterNotes: "tenantId and userId default to configured defaults when omitted.",
      responseShape: "{ ok, status, data: { scope, policy } }",
      failureConditions: "Postgres access failures.",
      prereqTools: ["jumpcloud_scope_info"],
      followUpTools: ["jumpcloud_tenant_policy_set", "jumpcloud_tenant_scope_validate"]
    },
    {
      name: "jumpcloud_tenant_policy_set",
      category: "mutating",
      risk: "high",
      whenToUse: "Use to set tenant/user policy guardrails for domain/method/path/mutation control.",
      whenNotToUse: "Do not use for token or non-policy config changes.",
      permissions: "Requires authorizationKey when MCP_ADMIN_AUTH_KEY is configured.",
      environmentBehavior: "Writes policy keys in scoped Postgres config.",
      parameterNotes: "Accepts partial updates; only provided fields are written.",
      responseShape: "{ ok, status, data: { scope, policy, updatedKeys } }",
      failureConditions: "Postgres write failures.",
      prereqTools: ["jumpcloud_tenant_policy_get"],
      followUpTools: ["jumpcloud_tenant_scope_validate", "jumpcloud_health_check"],
      safetyWarnings: "Overly restrictive rules can block API workflows for the scope."
    },
    {
      name: "jumpcloud_operation_invoke",
      category: "read-only-or-mutating",
      risk: "variable",
      whenToUse: "Use to execute a known OpenAPI operationId with structured path/query/body inputs.",
      whenNotToUse: "Do not use if you only have raw method+path; use jumpcloud_api_request instead.",
      permissions: "Uses per-user token from Vault. Requires authorizationKey if operation method is mutating and MCP_ADMIN_AUTH_KEY is configured.",
      environmentBehavior: "Domain inferred from operationId metadata.",
      parameterNotes: "pathParams keys must match path template parameters.",
      responseShape: "{ ok, status, data: { domain, method, path, status, data } }",
      failureConditions: "Unknown operationId, missing path params, token missing, JumpCloud API errors.",
      prereqTools: ["jumpcloud_user_token_upsert", "jumpcloud_openapi_discovery"],
      followUpTools: ["jumpcloud_api_request"],
      safetyWarnings: "Mutation operations can change production identities/devices. Validate operationId and payload first.",
      examples: [
        {
          name: "jumpcloud_operation_invoke",
          arguments: {
            userId: "team-a",
            operationId: "systemusers_list",
            query: {
              limit: 10
            }
          }
        }
      ]
    },
    {
      name: "jumpcloud_api_request",
      category: "read-only-or-mutating",
      risk: "variable",
      whenToUse: "Use for complete API coverage with explicit HTTP method/path when a dedicated operation call is not preferred.",
      whenNotToUse: "Do not use for planning/discovery-only tasks.",
      permissions: "Uses per-user token from Vault. Requires authorizationKey for mutating methods when MCP_ADMIN_AUTH_KEY is configured.",
      environmentBehavior: "Routes to console or directory-insights base URL by selected domain.",
      parameterNotes: "path must start with '/'; query accepts scalar values; body supports JSON.",
      responseShape: "{ ok, status, data: { domain, method, path, status, data } }",
      failureConditions: "Missing token, invalid path, timeout, auth errors, JumpCloud API errors.",
      prereqTools: ["jumpcloud_user_token_upsert", "jumpcloud_openapi_discovery"],
      followUpTools: ["jumpcloud_query_suggestion"],
      safetyWarnings: "Mutating calls are high risk for production directories.",
      examples: [
        {
          name: "jumpcloud_api_request",
          arguments: {
            userId: "default",
            domain: "console",
            method: "GET",
            path: "/api/systemusers"
          }
        }
      ],
      adminAuthConfigured
    },
    {
      name: "jumpcloud_user_token_upsert",
      category: "mutating",
      risk: "high",
      whenToUse: "Create or update a user-scoped JumpCloud token in Vault.",
      whenNotToUse: "Do not use for listing or read-only inspection.",
      permissions: "Requires authorizationKey when MCP_ADMIN_AUTH_KEY is configured.",
      environmentBehavior: "Writes secret to app/user-scoped Vault path.",
      parameterNotes: "tokenType supports 'apiKey' or 'bearer'.",
      responseShape: "{ ok, status, data: { userId, tokenId, activeTokenId } }",
      failureConditions: "Vault unavailable, invalid token payload.",
      prereqTools: ["jumpcloud_scope_info"],
      followUpTools: ["jumpcloud_user_token_set_active", "jumpcloud_api_request"],
      safetyWarnings: "Stores sensitive secrets. Token values are redacted in normal output."
    },
    {
      name: "jumpcloud_user_token_set_active",
      category: "mutating",
      risk: "medium",
      whenToUse: "Switch active token used by API tools for a specific user.",
      whenNotToUse: "Do not use to create tokens.",
      permissions: "Requires authorizationKey when MCP_ADMIN_AUTH_KEY is configured.",
      environmentBehavior: "Updates activeTokenId in user Vault token document.",
      parameterNotes: "tokenId must exist for that user.",
      responseShape: "{ ok, status, data: { userId, activeTokenId } }",
      failureConditions: "Missing tokenId for user, Vault write errors.",
      prereqTools: ["jumpcloud_user_token_upsert"],
      followUpTools: ["jumpcloud_api_request"]
    },
    {
      name: "jumpcloud_user_token_list",
      category: "read-only",
      risk: "medium",
      whenToUse: "Inspect token metadata for a user and verify active token selection.",
      whenNotToUse: "Do not use to reveal secret values unless explicitly allowed.",
      permissions: "Read-only. No admin key required.",
      environmentBehavior: "Reads user-scoped token document from Vault.",
      parameterNotes: "includeSensitive is false by default and should remain false in most flows.",
      responseShape: "{ ok, status, data: { userId, activeTokenId, tokens } }",
      failureConditions: "Vault read failures.",
      prereqTools: ["jumpcloud_scope_info"],
      followUpTools: ["jumpcloud_user_token_set_active", "jumpcloud_user_token_delete"]
    },
    {
      name: "jumpcloud_user_token_delete",
      category: "mutating",
      risk: "high",
      whenToUse: "Remove a token from a user token set.",
      whenNotToUse: "Do not use when only deactivation or switch is needed.",
      permissions: "Requires authorizationKey when MCP_ADMIN_AUTH_KEY is configured.",
      environmentBehavior: "Deletes token entry in Vault and may change active token fallback.",
      parameterNotes: "If deleting active token, first remaining token becomes active if present.",
      responseShape: "{ ok, status, data: { userId, activeTokenId, remainingTokenCount } }",
      failureConditions: "Vault write failures.",
      prereqTools: ["jumpcloud_user_token_list"],
      followUpTools: ["jumpcloud_user_token_upsert"],
      safetyWarnings: "Destructive action; validate userId + tokenId before execution."
    },
    {
      name: "jumpcloud_config_set",
      category: "mutating",
      risk: "medium",
      whenToUse: "Persist non-secret MCP configuration in Postgres.",
      whenNotToUse: "Do not store secrets here; use Vault token tools.",
      permissions: "Requires authorizationKey when MCP_ADMIN_AUTH_KEY is configured.",
      environmentBehavior: "Writes app/user-scoped key/value into Postgres config table.",
      parameterNotes: "value must be JSON-serializable.",
      responseShape: "{ ok, status, data: { user_id, key, value, updated_at } }",
      failureConditions: "Postgres connectivity, invalid JSON value.",
      prereqTools: ["jumpcloud_scope_info"],
      followUpTools: ["jumpcloud_config_get", "jumpcloud_config_list"]
    },
    {
      name: "jumpcloud_config_delete",
      category: "mutating",
      risk: "high",
      whenToUse: "Delete app/user config entries no longer needed.",
      whenNotToUse: "Do not use if config should be retained for rollback.",
      permissions: "Requires authorizationKey when MCP_ADMIN_AUTH_KEY is configured.",
      environmentBehavior: "Deletes row in Postgres app config table.",
      parameterNotes: "key must exactly match existing entry.",
      responseShape: "{ ok, status, data: { deleted } }",
      failureConditions: "Postgres write errors.",
      prereqTools: ["jumpcloud_config_get"],
      followUpTools: ["jumpcloud_config_set"],
      safetyWarnings: "Destructive operation; verify key and user scope before deletion."
    }
  ];
}

export function createMcpServer({
  name,
  version,
  serviceClient,
  configStore,
  allowSensitiveOutput = false,
  appName = "jumpcloud",
  defaultTenantId = "default",
  defaultUserId = "default"
}) {
  const server = new McpServer({
    name,
    version
  });

  const adminAuthKey = process.env.MCP_ADMIN_AUTH_KEY;
  const TENANT_POLICY_KEYS = {
    allowMutations: "jumpcloud.policy.allowMutations",
    allowedDomains: "jumpcloud.policy.allowedDomains",
    allowedMethods: "jumpcloud.policy.allowedMethods",
    allowedPathPrefixes: "jumpcloud.policy.allowedPathPrefixes",
    enforceMutationOperationAllowList: "jumpcloud.policy.enforceMutationOperationAllowList",
    allowedOperationIds: "jumpcloud.policy.allowedOperationIds"
  };

  function assertAdminAuthorized(authorizationKey, reason) {
    if (!adminAuthKey) {
      return;
    }

    if (!authorizationKey || authorizationKey !== adminAuthKey) {
      const unauthorized = new Error(`Unauthorized: invalid authorizationKey for ${reason}`);
      unauthorized.status = 401;
      throw unauthorized;
    }
  }

  function effectiveScope(tenantId, userId) {
    const resolvedTenantId = String(tenantId ?? defaultTenantId).trim() || defaultTenantId;
    const resolvedUserId = String(userId ?? defaultUserId).trim() || defaultUserId;
    return {
      tenantId: resolvedTenantId,
      userId: resolvedUserId
    };
  }

  async function getTenantPolicy(scope) {
    const [allowMutations, allowedDomains, allowedMethods, allowedPathPrefixes, enforceMutationOperationAllowList, allowedOperationIds] =
      await Promise.all([
        configStore.getConfig(TENANT_POLICY_KEYS.allowMutations, scope.tenantId, scope.userId),
        configStore.getConfig(TENANT_POLICY_KEYS.allowedDomains, scope.tenantId, scope.userId),
        configStore.getConfig(TENANT_POLICY_KEYS.allowedMethods, scope.tenantId, scope.userId),
        configStore.getConfig(TENANT_POLICY_KEYS.allowedPathPrefixes, scope.tenantId, scope.userId),
        configStore.getConfig(TENANT_POLICY_KEYS.enforceMutationOperationAllowList, scope.tenantId, scope.userId),
        configStore.getConfig(TENANT_POLICY_KEYS.allowedOperationIds, scope.tenantId, scope.userId)
      ]);

    return {
      allowMutations: toBoolean(allowMutations?.value, true),
      allowedDomains: toStringArray(allowedDomains?.value),
      allowedMethods: toStringArray(allowedMethods?.value, { upper: true }),
      allowedPathPrefixes: toStringArray(allowedPathPrefixes?.value),
      enforceMutationOperationAllowList: toBoolean(enforceMutationOperationAllowList?.value, false),
      allowedOperationIds: toStringArray(allowedOperationIds?.value)
    };
  }

  function assertPolicyAllows({ scope, policy, domain, method, path, operationId }) {
    const normalizedMethod = normalizeMethod(method);
    const normalizedPath = normalizePath(path);
    const normalizedDomain = String(domain ?? "").trim().toLowerCase();
    const mutating = MUTATING_METHODS.has(normalizedMethod);

    if (policy.allowedDomains.length > 0 && normalizedDomain && !policy.allowedDomains.includes(normalizedDomain)) {
      const error = new Error(
        `Tenant policy denied domain '${normalizedDomain}' for scope '${scope.tenantId}/${scope.userId}'`
      );
      error.status = 403;
      throw error;
    }

    if (policy.allowedMethods.length > 0 && !policy.allowedMethods.includes(normalizedMethod)) {
      const error = new Error(
        `Tenant policy denied method '${normalizedMethod}' for scope '${scope.tenantId}/${scope.userId}'`
      );
      error.status = 403;
      throw error;
    }

    if (policy.allowedPathPrefixes.length > 0) {
      const allowed = policy.allowedPathPrefixes.some((prefix) => normalizedPath.startsWith(normalizePath(prefix)));
      if (!allowed) {
        const error = new Error(
          `Tenant policy denied path '${normalizedPath}' for scope '${scope.tenantId}/${scope.userId}'`
        );
        error.status = 403;
        throw error;
      }
    }

    if (mutating && !policy.allowMutations) {
      const error = new Error(`Tenant policy denied mutating operation for scope '${scope.tenantId}/${scope.userId}'`);
      error.status = 403;
      throw error;
    }

    if (mutating && policy.enforceMutationOperationAllowList) {
      if (!operationId || !policy.allowedOperationIds.includes(operationId)) {
        const error = new Error(
          `Tenant policy denied operationId '${operationId ?? "unknown"}' for scope '${scope.tenantId}/${scope.userId}'`
        );
        error.status = 403;
        throw error;
      }
    }
  }

  server.tool(
    "jumpcloud_connection_info",
    "Read-only runtime metadata. Use when validating configured base URLs, OpenAPI source URLs, and persistence wiring. Do not use for API execution. Risk: low.",
    {},
    withErrorHandling(async () => ({
      ok: true,
      status: 200,
      data: {
        server: {
          name,
          version,
          appName,
          defaultTenantId,
          defaultUserId,
          adminAuthConfigured: Boolean(adminAuthKey)
        },
        jumpcloud: serviceClient.getConnectionInfo(),
        persistence: {
          secrets: "vault",
          configuration: "postgres"
        }
      }
    }))
  );

  server.tool(
    "jumpcloud_scope_info",
    "Read-only scope resolver. Use when you need the effective app/tenant/user scope and storage locations. Do not use for mutation. Risk: low.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional()
    },
    withErrorHandling(async ({ tenantId, userId }) => {
      const scope = effectiveScope(tenantId, userId);
      return {
        ok: true,
        status: 200,
        data: {
          appName,
          tenantId: scope.tenantId,
          userId: scope.userId,
          vaultTokenPath: serviceClient.getUserTokenPath(scope.tenantId, scope.userId),
          postgresConfigTable: configStore.tableName,
          postgresScopeId: `${scope.tenantId}/${scope.userId}`
        }
      };
    })
  );

  server.tool(
    "jumpcloud_openapi_discovery",
    "Read-only OpenAPI discovery. Use to search operationId/method/path/tag metadata before invocation. Do not use as an execution tool. Risk: low.",
    {
      domain: z.enum(["console", "directory-insights"]).optional(),
      search: z.string().optional(),
      limit: z.number().int().positive().max(500).optional()
    },
    withErrorHandling(async ({ domain, search, limit }) => ({
      ok: true,
      status: 200,
      data: await serviceClient.listKnownEndpoints({ domain, search, limit: limit ?? 200 })
    }))
  );

  server.tool(
    "jumpcloud_tenant_list",
    "Read-only tenant discovery. Use to list tenant ids and optionally discover scoped users from Postgres and Vault token paths. Do not use for mutation. Risk: low.",
    {
      includeUsers: z.boolean().optional()
    },
    withErrorHandling(async ({ includeUsers }) => {
      const tenantIds = await configStore.listTenants();

      if (includeUsers !== true) {
        return {
          ok: true,
          status: 200,
          data: {
            count: tenantIds.length,
            tenants: tenantIds
          }
        };
      }

      const tenants = [];
      for (const tenantId of tenantIds) {
        const [configUsers, vaultUsers] = await Promise.all([
          configStore.listUsersByTenant(tenantId),
          serviceClient.listTenantUsersWithTokens(tenantId)
        ]);

        tenants.push({
          tenantId,
          users: {
            postgresConfig: configUsers,
            vaultTokens: vaultUsers
          }
        });
      }

      return {
        ok: true,
        status: 200,
        data: {
          count: tenants.length,
          tenants
        }
      };
    })
  );

  server.tool(
    "jumpcloud_tenant_scope_validate",
    "Read-only tenant/user scope validation. Use to confirm token and config readiness before operational API calls. Risk: medium.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional()
    },
    withErrorHandling(async ({ tenantId, userId }) => {
      const scope = effectiveScope(tenantId, userId);
      const tokenDoc = await serviceClient.getUserTokens(scope.tenantId, scope.userId, {
        includeSensitive: false
      });
      const configs = await configStore.listConfigs(undefined, scope.tenantId, scope.userId);

      const hasActiveToken = Boolean(tokenDoc.activeTokenId);
      const hasAnyToken = Object.keys(tokenDoc.tokens ?? {}).length > 0;
      const hasConfig = Array.isArray(configs) && configs.length > 0;

      return {
        ok: true,
        status: 200,
        data: {
          scope,
          checks: {
            hasAnyToken,
            hasActiveToken,
            hasConfig
          },
          recommendations: [
            ...(hasAnyToken ? [] : ["Run jumpcloud_user_token_upsert to seed a token for this scope."]),
            ...(hasActiveToken ? [] : ["Run jumpcloud_user_token_set_active to set an active token."]),
            ...(hasConfig ? [] : ["Run jumpcloud_tenant_bootstrap_defaults to initialize baseline config."])
          ]
        }
      };
    })
  );

  server.tool(
    "jumpcloud_tenant_bootstrap_defaults",
    "Mutating tenant/user baseline config initializer. Use to write recommended non-secret defaults for a scope. Risk: high.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      defaults: z.record(z.string(), z.unknown()).optional(),
      authorizationKey: z.string().optional()
    },
    withErrorHandling(async ({ tenantId, userId, defaults, authorizationKey }) => {
      assertAdminAuthorized(authorizationKey, "tenant bootstrap defaults");
      const scope = effectiveScope(tenantId, userId);

      const baseline = {
        "jumpcloud.defaultDomain": "console",
        "jumpcloud.timeoutMs": 20000,
        "jumpcloud.bootstrap.version": 1,
        "jumpcloud.bootstrap.updatedAt": new Date().toISOString(),
        [TENANT_POLICY_KEYS.allowMutations]: true,
        [TENANT_POLICY_KEYS.allowedDomains]: ["console", "directory-insights"],
        [TENANT_POLICY_KEYS.allowedMethods]: ["GET", "POST", "PUT", "PATCH", "DELETE"],
        [TENANT_POLICY_KEYS.allowedPathPrefixes]: [],
        [TENANT_POLICY_KEYS.enforceMutationOperationAllowList]: false,
        [TENANT_POLICY_KEYS.allowedOperationIds]: [],
        ...(defaults ?? {})
      };

      const records = [];
      for (const [key, value] of Object.entries(baseline)) {
        records.push(await configStore.setConfig(key, value, scope.tenantId, scope.userId));
      }

      return {
        ok: true,
        status: 200,
        data: {
          scope,
          appliedDefaults: Object.keys(baseline),
          records
        }
      };
    })
  );

  server.tool(
    "jumpcloud_tenant_policy_get",
    "Read-only tenant/user policy reader. Use to inspect effective policy guardrails for a scope. Risk: medium.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional()
    },
    withErrorHandling(async ({ tenantId, userId }) => {
      const scope = effectiveScope(tenantId, userId);
      return {
        ok: true,
        status: 200,
        data: {
          scope,
          policy: await getTenantPolicy(scope)
        }
      };
    })
  );

  server.tool(
    "jumpcloud_tenant_policy_set",
    "Mutating tenant/user policy writer. Use to update scoped policy guardrails for API execution. Risk: high.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      allowMutations: z.boolean().optional(),
      allowedDomains: z.array(z.enum(["console", "directory-insights"])).optional(),
      allowedMethods: z.array(z.string().min(1)).optional(),
      allowedPathPrefixes: z.array(z.string().min(1)).optional(),
      enforceMutationOperationAllowList: z.boolean().optional(),
      allowedOperationIds: z.array(z.string().min(1)).optional(),
      authorizationKey: z.string().optional()
    },
    withErrorHandling(async (args) => {
      assertAdminAuthorized(args.authorizationKey, "tenant policy update");
      const scope = effectiveScope(args.tenantId, args.userId);

      const updates = [];
      if (args.allowMutations !== undefined) {
        updates.push([TENANT_POLICY_KEYS.allowMutations, args.allowMutations]);
      }
      if (args.allowedDomains !== undefined) {
        updates.push([TENANT_POLICY_KEYS.allowedDomains, args.allowedDomains]);
      }
      if (args.allowedMethods !== undefined) {
        updates.push([TENANT_POLICY_KEYS.allowedMethods, args.allowedMethods.map((method) => normalizeMethod(method))]);
      }
      if (args.allowedPathPrefixes !== undefined) {
        updates.push([TENANT_POLICY_KEYS.allowedPathPrefixes, args.allowedPathPrefixes.map((path) => normalizePath(path))]);
      }
      if (args.enforceMutationOperationAllowList !== undefined) {
        updates.push([TENANT_POLICY_KEYS.enforceMutationOperationAllowList, args.enforceMutationOperationAllowList]);
      }
      if (args.allowedOperationIds !== undefined) {
        updates.push([TENANT_POLICY_KEYS.allowedOperationIds, args.allowedOperationIds]);
      }

      for (const [key, value] of updates) {
        await configStore.setConfig(key, value, scope.tenantId, scope.userId);
      }

      return {
        ok: true,
        status: 200,
        data: {
          scope,
          updatedKeys: updates.map(([key]) => key),
          policy: await getTenantPolicy(scope)
        }
      };
    })
  );

  server.tool(
    "jumpcloud_query_suggestion",
    "Read-only planning helper. Use to choose safe tool order, discover likely operations, and retrieve tool usage schema details. Do not use for direct mutations. Risk: low.",
    {
      intent: z.string().optional(),
      domain: z.enum(["console", "directory-insights"]).optional(),
      method: z.string().optional(),
      path: z.string().optional(),
      includeToolSchemas: z.boolean().optional()
    },
    withErrorHandling(async ({ intent, domain, method, path, includeToolSchemas }) => {
      const normalizedMethod = method ? normalizeMethod(method) : null;
      const normalizedPath = path ? normalizePath(path) : null;
      const suggestions = await serviceClient.suggestOperations({
        intent,
        method: normalizedMethod,
        path: normalizedPath,
        domain
      });

      const mutatingRequested = suggestions.some((entry) => entry.isMutating) || requiresAdminKey(adminAuthKey, normalizedMethod);

      const payload = {
        ok: true,
        status: 200,
        data: {
          summary: {
            intent: intent ?? null,
            domain: domain ?? null,
            method: normalizedMethod,
            path: normalizedPath,
            mutatingRequested,
            adminAuthorizationRequired: Boolean(adminAuthKey) && mutatingRequested
          },
          recommendedOrder: [
            {
              tool: "jumpcloud_connection_info",
              reason: "Verify runtime wiring and auth mode before operational calls."
            },
            {
              tool: "jumpcloud_user_token_list",
              reason: "Confirm active per-tenant/user token exists in Vault."
            },
            {
              tool: "jumpcloud_openapi_discovery",
              reason: "Validate operation metadata and expected path/method."
            },
            {
              tool: suggestions.length > 0 ? "jumpcloud_operation_invoke" : "jumpcloud_api_request",
              reason: "Execute using discovered operation metadata or explicit method/path."
            }
          ],
          suggestedOperations: suggestions,
          safetyChecks: [
            "Confirm the intended tenantId and userId before executing any request.",
            "For mutating operations, require explicit authorizationKey when MCP_ADMIN_AUTH_KEY is configured.",
            "Use jumpcloud_openapi_discovery to confirm path and method before mutating calls.",
            "Store API keys only in Vault via jumpcloud_user_token_upsert; never in config tools."
          ]
        }
      };

      if (includeToolSchemas !== false) {
        payload.data.toolSchemas = buildToolSchemas({ adminAuthConfigured: Boolean(adminAuthKey) });
      }

      return payload;
    })
  );

  server.tool(
    "jumpcloud_user_token_list",
    "Read-only token metadata listing. Use to inspect user-scoped token entries and active token selection. Do not use to rotate/update secrets. Risk: medium.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      includeSensitive: z.boolean().optional()
    },
    withErrorHandling(async ({ tenantId, userId, includeSensitive }) => {
      const scope = effectiveScope(tenantId, userId);
      return {
        ok: true,
        status: 200,
        data: redactObject(
          await serviceClient.getUserTokens(scope.tenantId, scope.userId, {
            includeSensitive: includeSensitive === true && allowSensitiveOutput
          }),
          includeSensitive === true && allowSensitiveOutput
        )
      };
    })
  );

  server.tool(
    "jumpcloud_user_token_upsert",
    "Mutating token create/update. Use to add or rotate JumpCloud user tokens in Vault. Do not use for read-only workflows. Risk: high.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1),
      value: z.string().min(1),
      tokenType: z.enum(["apiKey", "bearer"]).optional(),
      headerName: z.string().min(1).optional(),
      description: z.string().optional(),
      authorizationKey: z.string().optional()
    },
    withErrorHandling(async ({ tenantId, userId, tokenId, value, tokenType, headerName, description, authorizationKey }) => {
      assertAdminAuthorized(authorizationKey, "token update");

      const scope = effectiveScope(tenantId, userId);

      return {
        ok: true,
        status: 200,
        data: await serviceClient.upsertUserToken({
          tenantId: scope.tenantId,
          userId: scope.userId,
          tokenId,
          value,
          tokenType,
          headerName,
          description
        })
      };
    })
  );

  server.tool(
    "jumpcloud_user_token_set_active",
    "Mutating token selection. Use to change active token for a user. Do not use to create tokens. Risk: medium.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1),
      authorizationKey: z.string().optional()
    },
    withErrorHandling(async ({ tenantId, userId, tokenId, authorizationKey }) => {
      assertAdminAuthorized(authorizationKey, "token update");
      const scope = effectiveScope(tenantId, userId);
      return {
        ok: true,
        status: 200,
        data: await serviceClient.setActiveUserToken({
          tenantId: scope.tenantId,
          userId: scope.userId,
          tokenId
        })
      };
    })
  );

  server.tool(
    "jumpcloud_user_token_delete",
    "Mutating token deletion. Use when removing obsolete user tokens from Vault. Destructive. Risk: high.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1),
      authorizationKey: z.string().optional()
    },
    withErrorHandling(async ({ tenantId, userId, tokenId, authorizationKey }) => {
      assertAdminAuthorized(authorizationKey, "token deletion");
      const scope = effectiveScope(tenantId, userId);
      return {
        ok: true,
        status: 200,
        data: await serviceClient.deleteUserToken({
          tenantId: scope.tenantId,
          userId: scope.userId,
          tokenId
        })
      };
    })
  );

  server.tool(
    "jumpcloud_config_list",
    "Read-only Postgres config listing. Use to enumerate app/user scoped non-secret configuration values. Do not store secrets in config. Risk: low.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      prefix: z.string().optional()
    },
    withErrorHandling(async ({ tenantId, userId, prefix }) => {
      const scope = effectiveScope(tenantId, userId);
      return {
        ok: true,
        status: 200,
        data: await configStore.listConfigs(prefix, scope.tenantId, scope.userId)
      };
    })
  );

  server.tool(
    "jumpcloud_config_get",
    "Read-only Postgres config getter. Use to fetch one user-scoped configuration key. Risk: low.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      key: z.string().min(1)
    },
    withErrorHandling(async ({ tenantId, userId, key }) => {
      const scope = effectiveScope(tenantId, userId);
      return {
        ok: true,
        status: 200,
        data: await configStore.getConfig(key, scope.tenantId, scope.userId)
      };
    })
  );

  server.tool(
    "jumpcloud_config_set",
    "Mutating Postgres config setter. Use for non-secret runtime configuration. Do not store token values. Risk: medium.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      key: z.string().min(1),
      value: z.unknown(),
      authorizationKey: z.string().optional()
    },
    withErrorHandling(async ({ tenantId, userId, key, value, authorizationKey }) => {
      assertAdminAuthorized(authorizationKey, "configuration update");
      const scope = effectiveScope(tenantId, userId);
      return {
        ok: true,
        status: 200,
        data: await configStore.setConfig(key, value, scope.tenantId, scope.userId)
      };
    })
  );

  server.tool(
    "jumpcloud_config_delete",
    "Mutating Postgres config delete. Use to remove obsolete non-secret settings. Destructive. Risk: high.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      key: z.string().min(1),
      authorizationKey: z.string().optional()
    },
    withErrorHandling(async ({ tenantId, userId, key, authorizationKey }) => {
      assertAdminAuthorized(authorizationKey, "configuration deletion");
      const scope = effectiveScope(tenantId, userId);
      return {
        ok: true,
        status: 200,
        data: {
          deleted: await configStore.deleteConfig(key, scope.tenantId, scope.userId)
        }
      };
    })
  );

  server.tool(
    "jumpcloud_health_check",
    "Read-only health and credential check against JumpCloud using current user's active token. Use before large workflows. Risk: low.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional()
    },
    withErrorHandling(async ({ tenantId, userId, tokenId }) => {
      const scope = effectiveScope(tenantId, userId);
      return {
        ok: true,
        status: 200,
        data: await serviceClient.healthCheck(scope.tenantId, scope.userId, tokenId)
      };
    })
  );

  server.tool(
    "jumpcloud_operation_invoke",
    "OpenAPI operation invoker. Use operationId+pathParams for high-fidelity execution with full API coverage. Mutating calls require admin key if configured. Risk: variable.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      operationId: z.string().min(1),
      pathParams: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
      query: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
      body: z.unknown().optional(),
      headers: z.record(z.string(), z.string()).optional(),
      authorizationKey: z.string().optional()
    },
    withErrorHandling(async ({ tenantId, userId, tokenId, operationId, pathParams, query, body, headers, authorizationKey }) => {
      const operation = await serviceClient.getOperationById(operationId);
      if (operation && MUTATING_METHODS.has(normalizeMethod(operation.method))) {
        assertAdminAuthorized(authorizationKey, "mutating OpenAPI operation");
      }

      const scope = effectiveScope(tenantId, userId);
      const policy = await getTenantPolicy(scope);
      assertPolicyAllows({
        scope,
        policy,
        domain: operation?.domain,
        method: operation?.method ?? "GET",
        path: operation?.pathTemplate ?? "/",
        operationId
      });

      return {
        ok: true,
        status: 200,
        data: await serviceClient.requestByOperation({
          tenantId: scope.tenantId,
          userId: scope.userId,
          tokenId,
          operationId,
          pathParams,
          query,
          body,
          headers
        })
      };
    })
  );

  server.tool(
    "jumpcloud_api_request",
    "Generic JumpCloud request executor. Use for explicit domain/method/path calls with full endpoint coverage. Mutations require admin key if configured. Risk: variable.",
    {
      tenantId: z.string().min(1).optional(),
      userId: z.string().min(1).optional(),
      tokenId: z.string().min(1).optional(),
      domain: z.enum(["console", "directory-insights"]).optional(),
      method: z.string().min(1),
      path: z.string().min(1),
      query: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
      body: z.unknown().optional(),
      headers: z.record(z.string(), z.string()).optional(),
      authorizationKey: z.string().optional()
    },
    withErrorHandling(async ({ tenantId, userId, tokenId, domain, method, path, query, body, headers, authorizationKey }) => {
      const normalizedMethod = normalizeMethod(method);
      if (MUTATING_METHODS.has(normalizedMethod)) {
        assertAdminAuthorized(authorizationKey, "mutating API request");
      }

      const scope = effectiveScope(tenantId, userId);
      const policy = await getTenantPolicy(scope);
      assertPolicyAllows({
        scope,
        policy,
        domain,
        method: normalizedMethod,
        path,
        operationId: null
      });

      return {
        ok: true,
        status: 200,
        data: await serviceClient.request({
          tenantId: scope.tenantId,
          userId: scope.userId,
          tokenId,
          domain,
          method: normalizedMethod,
          path: normalizePath(path),
          query,
          body,
          headers
        })
      };
    })
  );

  return server;
}
