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
    getUserTokenPath(userId) {
      return `jumpcloud/users/${userId}/jumpcloud/tokens`;
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
    async getUserTokens(userId) {
      return {
        userId,
        activeTokenId: "primary",
        tokens: tokensByUser.get(userId) ?? {}
      };
    },
    async upsertUserToken({ userId, tokenId }) {
      calls.upsert += 1;
      const existing = tokensByUser.get(userId) ?? {};
      existing[tokenId] = {
        tokenId,
        value: "[REDACTED]",
        active: true
      };
      tokensByUser.set(userId, existing);
      return { userId, tokenId, activeTokenId: tokenId };
    },
    async setActiveUserToken({ userId, tokenId }) {
      calls.setActive += 1;
      return { userId, activeTokenId: tokenId };
    },
    async deleteUserToken({ userId, tokenId }) {
      calls.remove += 1;
      return { userId, activeTokenId: null, remainingTokenCount: 0, deletedTokenId: tokenId };
    },
    async healthCheck(userId, tokenId) {
      return { status: 200, userId, tokenId };
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
    }
  };

  return { client, calls };
}

function createConfigStoreMock() {
  const records = new Map();

  return {
    tableName: "jumpcloud_config",
    async listConfigs(prefix = "", userId = "default") {
      const output = [];
      for (const [key, value] of records.entries()) {
        if (key.startsWith(`${userId}:`) && (!prefix || key.slice(userId.length + 1).startsWith(prefix))) {
          output.push({ key: key.slice(userId.length + 1), value });
        }
      }
      return output;
    },
    async getConfig(key, userId = "default") {
      const value = records.get(`${userId}:${key}`);
      return value === undefined ? null : { user_id: userId, key, value };
    },
    async setConfig(key, value, userId = "default") {
      records.set(`${userId}:${key}`, value);
      return { user_id: userId, key, value };
    },
    async deleteConfig(key, userId = "default") {
      return records.delete(`${userId}:${key}`);
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
