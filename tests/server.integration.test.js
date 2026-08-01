import assert from "node:assert/strict";
import test from "node:test";

import { createMcpServer } from "../src/mcp/server.js";

function setEnv(updates) {
  const previous = {};
  for (const [key, value] of Object.entries(updates)) {
    previous[key] = process.env[key];
    if (value === undefined || value === null) {
      delete process.env[key];
    } else {
      process.env[key] = String(value);
    }
  }

  return () => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  };
}

function createServiceClientMock() {
  const calls = {
    request: 0,
    requestByOperation: 0,
    upsert: 0,
    setActive: 0,
    remove: 0
  };

  const tokensByUser = new Map();

  const client = {
    getConnectionInfo() {
      return {
        consoleBaseUrl: "https://console.jumpcloud.com",
        directoryInsightsBaseUrl: "https://api.jumpcloud.com"
      };
    },
    getUserTokenPath(tenantId, userId) {
      return `jumpcloud/tenants/${tenantId}/users/${userId}/jumpcloud/tokens`;
    },
    async listKnownEndpoints() {
      return {
        count: 1,
        endpoints: [
          {
            domain: "console",
            operationId: "systemusers_list",
            method: "GET",
            path: "/api/systemusers"
          }
        ]
      };
    },
    async suggestOperations() {
      return [
        {
          operationId: "systemusers_list",
          method: "GET",
          path: "/api/systemusers",
          domain: "console",
          isMutating: false
        },
        {
          operationId: "systemusers_update",
          method: "PUT",
          path: "/api/systemusers/{id}",
          domain: "console",
          isMutating: true
        }
      ];
    },
    async getOperationById(operationId) {
      if (operationId === "systemusers_update") {
        return { operationId, method: "PUT" };
      }
      return { operationId, method: "GET" };
    },
    async getUserTokens(tenantId, userId) {
      return {
        tenantId,
        userId,
        activeTokenId: "primary",
        tokens: tokensByUser.get(`${tenantId}/${userId}`) ?? {}
      };
    },
    async upsertUserToken({ tenantId, userId, tokenId }) {
      calls.upsert += 1;
      const scopeId = `${tenantId}/${userId}`;
      const existing = tokensByUser.get(scopeId) ?? {};
      existing[tokenId] = {
        tokenId,
        value: "[REDACTED]",
        active: true
      };
      tokensByUser.set(scopeId, existing);
      return { tenantId, userId, tokenId, activeTokenId: tokenId };
    },
    async setActiveUserToken({ tenantId, userId, tokenId }) {
      calls.setActive += 1;
      return { tenantId, userId, activeTokenId: tokenId };
    },
    async deleteUserToken({ tenantId, userId, tokenId }) {
      calls.remove += 1;
      return { tenantId, userId, activeTokenId: null, remainingTokenCount: 0, deletedTokenId: tokenId };
    },
    async healthCheck(tenantId, userId, tokenId) {
      return { status: 200, tenantId, userId, tokenId };
    },
    async request(payload) {
      calls.request += 1;
      return {
        status: 200,
        ...payload
      };
    },
    async requestByOperation(payload) {
      calls.requestByOperation += 1;
      return {
        status: 200,
        ...payload
      };
    },
    async listTenantUsersWithTokens(tenantId) {
      if (tenantId === "tenant-a") {
        return ["team-a", "ops"];
      }
      return [];
    }
  };

  return { client, calls };
}

function createConfigStoreMock() {
  const records = new Map();

  return {
    tableName: "jumpcloud_config",
    async listConfigs(prefix = "", tenantId = "default", userId = "default") {
      const output = [];
      for (const [key, value] of records.entries()) {
        const scopePrefix = `${tenantId}/${userId}:`;
        if (key.startsWith(scopePrefix) && (!prefix || key.slice(scopePrefix.length).startsWith(prefix))) {
          output.push({ key: key.slice(scopePrefix.length), value, tenant_id: tenantId, scoped_user_id: userId });
        }
      }
      return output;
    },
    async getConfig(key, tenantId = "default", userId = "default") {
      const value = records.get(`${tenantId}/${userId}:${key}`);
      return value === undefined ? null : { user_id: `${tenantId}/${userId}`, tenant_id: tenantId, scoped_user_id: userId, key, value };
    },
    async setConfig(key, value, tenantId = "default", userId = "default") {
      records.set(`${tenantId}/${userId}:${key}`, value);
      return { user_id: `${tenantId}/${userId}`, tenant_id: tenantId, scoped_user_id: userId, key, value };
    },
    async deleteConfig(key, tenantId = "default", userId = "default") {
      return records.delete(`${tenantId}/${userId}:${key}`);
    },
    async listTenants() {
      const tenantSet = new Set();
      for (const scopedKey of records.keys()) {
        const scopePart = String(scopedKey).split(":")[0];
        const tenantPart = scopePart.split("/")[0] || "default";
        tenantSet.add(tenantPart);
      }
      return Array.from(tenantSet).sort((a, b) => a.localeCompare(b));
    },
    async listUsersByTenant(tenantId = "default") {
      const userSet = new Set();
      for (const scopedKey of records.keys()) {
        const scopePart = String(scopedKey).split(":")[0];
        const [tenantPart, userPart] = scopePart.split("/");
        if (tenantPart === tenantId && userPart) {
          userSet.add(userPart);
        }
      }
      return Array.from(userSet).sort((a, b) => a.localeCompare(b));
    }
  };
}

async function invokeTool(server, name, args = {}) {
  const registeredTools = server._registeredTools;
  assert.ok(registeredTools[name], `Expected tool ${name} to be registered`);
  const result = await registeredTools[name].handler(args);
  const payload = JSON.parse(result.content[0].text);
  return { result, payload };
}

test("jumpcloud_query_suggestion returns suggested operations and tool schemas", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "" });

  try {
    const { client } = createServiceClientMock();
    const server = createMcpServer({
      name: "jumpcloud-mcp",
      version: "0.1.0",
      serviceClient: client,
      configStore: createConfigStoreMock(),
      appName: "jumpcloud",
      defaultTenantId: "default",
      defaultUserId: "default"
    });

    const { payload } = await invokeTool(server, "jumpcloud_query_suggestion", {
      intent: "list system users",
      domain: "console"
    });

    assert.equal(payload.ok, true);
    assert.equal(payload.status, 200);
    assert.equal(Array.isArray(payload.data.suggestedOperations), true);
    assert.equal(Array.isArray(payload.data.toolSchemas), true);
    assert.equal(payload.data.suggestedOperations.length > 0, true);
  } finally {
    restoreEnv();
  }
});

test("jumpcloud_api_request mutating method requires authorizationKey when admin key configured", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "super-secret" });

  try {
    const { client, calls } = createServiceClientMock();
    const server = createMcpServer({
      name: "jumpcloud-mcp",
      version: "0.1.0",
      serviceClient: client,
      configStore: createConfigStoreMock(),
      appName: "jumpcloud",
      defaultTenantId: "default",
      defaultUserId: "default"
    });

    const unauthorized = await invokeTool(server, "jumpcloud_api_request", {
      userId: "default",
      domain: "console",
      method: "POST",
      path: "/api/systemusers"
    });

    assert.equal(unauthorized.result.isError, true);
    assert.equal(unauthorized.payload.status, 401);

    const authorized = await invokeTool(server, "jumpcloud_api_request", {
      userId: "default",
      domain: "console",
      method: "POST",
      path: "/api/systemusers",
      authorizationKey: "super-secret"
    });

    assert.equal(authorized.payload.ok, true);
    assert.equal(calls.request, 1);
  } finally {
    restoreEnv();
  }
});

test("jumpcloud_user_token_upsert requires authorizationKey when admin key configured", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "super-secret" });

  try {
    const { client, calls } = createServiceClientMock();
    const server = createMcpServer({
      name: "jumpcloud-mcp",
      version: "0.1.0",
      serviceClient: client,
      configStore: createConfigStoreMock(),
      appName: "jumpcloud",
      defaultTenantId: "default",
      defaultUserId: "default"
    });

    const unauthorized = await invokeTool(server, "jumpcloud_user_token_upsert", {
      userId: "default",
      tokenId: "primary",
      value: "secret"
    });

    assert.equal(unauthorized.result.isError, true);
    assert.equal(unauthorized.payload.status, 401);

    const authorized = await invokeTool(server, "jumpcloud_user_token_upsert", {
      userId: "default",
      tokenId: "primary",
      value: "secret",
      authorizationKey: "super-secret"
    });

    assert.equal(authorized.payload.ok, true);
    assert.equal(calls.upsert, 1);
  } finally {
    restoreEnv();
  }
});

test("jumpcloud_config_set writes user-scoped config", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "" });

  try {
    const { client } = createServiceClientMock();
    const configStore = createConfigStoreMock();
    const server = createMcpServer({
      name: "jumpcloud-mcp",
      version: "0.1.0",
      serviceClient: client,
      configStore,
      appName: "jumpcloud",
      defaultTenantId: "default",
      defaultUserId: "default"
    });

    const setResult = await invokeTool(server, "jumpcloud_config_set", {
      userId: "team-a",
      key: "jumpcloud.defaultDomain",
      value: "console"
    });
    assert.equal(setResult.payload.ok, true);

    const getResult = await invokeTool(server, "jumpcloud_config_get", {
      userId: "team-a",
      key: "jumpcloud.defaultDomain"
    });

    assert.equal(getResult.payload.ok, true);
    assert.equal(getResult.payload.data.value, "console");
  } finally {
    restoreEnv();
  }
});

test("jumpcloud_tenant_bootstrap_defaults writes baseline defaults and tenant list includes tenant", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "" });

  try {
    const { client } = createServiceClientMock();
    const configStore = createConfigStoreMock();
    const server = createMcpServer({
      name: "jumpcloud-mcp",
      version: "0.1.0",
      serviceClient: client,
      configStore,
      appName: "jumpcloud",
      defaultTenantId: "default",
      defaultUserId: "default"
    });

    const bootstrap = await invokeTool(server, "jumpcloud_tenant_bootstrap_defaults", {
      tenantId: "tenant-a",
      userId: "ops"
    });
    assert.equal(bootstrap.payload.ok, true);
    assert.equal(Array.isArray(bootstrap.payload.data.appliedDefaults), true);

    const tenantList = await invokeTool(server, "jumpcloud_tenant_list", {
      includeUsers: true
    });
    assert.equal(tenantList.payload.ok, true);
    assert.equal(tenantList.payload.data.count > 0, true);
    const tenantEntry = tenantList.payload.data.tenants.find((entry) => entry.tenantId === "tenant-a");
    assert.ok(tenantEntry);
  } finally {
    restoreEnv();
  }
});

test("jumpcloud_tenant_scope_validate reports missing token and config recommendations", async () => {
  const restoreEnv = setEnv({ MCP_ADMIN_AUTH_KEY: "" });

  try {
    const { client } = createServiceClientMock();
    const configStore = createConfigStoreMock();
    const server = createMcpServer({
      name: "jumpcloud-mcp",
      version: "0.1.0",
      serviceClient: client,
      configStore,
      appName: "jumpcloud",
      defaultTenantId: "default",
      defaultUserId: "default"
    });

    const validation = await invokeTool(server, "jumpcloud_tenant_scope_validate", {
      tenantId: "tenant-z",
      userId: "auditor"
    });

    assert.equal(validation.payload.ok, true);
    assert.equal(validation.payload.data.checks.hasAnyToken, false);
    assert.equal(validation.payload.data.checks.hasConfig, false);
    assert.equal(Array.isArray(validation.payload.data.recommendations), true);
    assert.equal(validation.payload.data.recommendations.length > 0, true);
  } finally {
    restoreEnv();
  }
});
