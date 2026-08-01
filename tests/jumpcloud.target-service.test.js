import assert from "node:assert/strict";
import test from "node:test";

import { TargetServiceClient } from "../src/services/targetService.js";

const CONSOLE_SPEC = `openapi: 3.1.0
info:
  title: Console
  version: "1.0"
servers:
  - url: https://console.jumpcloud.com
paths:
  /api/systemusers:
    get:
      operationId: systemusers_list
      tags: [SystemUsers]
      summary: List system users
  /api/systemusers/{id}:
    put:
      operationId: systemusers_update
      tags: [SystemUsers]
      summary: Update system user
`;

const DIRECTORY_SPEC = `openapi: 3.1.0
info:
  title: Directory Insights
  version: "1.0"
servers:
  - url: https://api.jumpcloud.com
paths:
  /insights/directory/v1/events:
    post:
      operationId: directoryinsights_events_post
      tags: [DirectoryInsights]
      summary: Query events
`;

function createVaultMock() {
  const data = new Map();

  return {
    async getSecret(path) {
      return data.get(path) ?? null;
    },
    async setSecret(path, payload) {
      data.set(path, payload);
      return { ok: true };
    }
  };
}

function createFetchMock() {
  const calls = [];

  async function fetchMock(url, options = {}) {
    const target = String(url);
    calls.push({ url: target, options });

    if (target.includes("console-spec")) {
      return {
        ok: true,
        text: async () => CONSOLE_SPEC
      };
    }

    if (target.includes("directory-spec")) {
      return {
        ok: true,
        text: async () => DIRECTORY_SPEC
      };
    }

    return {
      ok: true,
      status: 200,
      headers: {
        get(name) {
          if (String(name).toLowerCase() === "content-type") {
            return "application/json";
          }
          return "";
        }
      },
      text: async () => JSON.stringify({ ok: true, url: target })
    };
  }

  return { fetchMock, calls };
}

test("TargetServiceClient discovers OpenAPI operations across both domains", async () => {
  const vault = createVaultMock();
  const { fetchMock } = createFetchMock();
  const originalFetch = global.fetch;
  global.fetch = fetchMock;

  try {
    const client = new TargetServiceClient({
      consoleBaseUrl: "https://console.jumpcloud.com",
      directoryInsightsBaseUrl: "https://api.jumpcloud.com",
      consoleSpecUrl: "https://example.test/console-spec.yaml",
      directoryInsightsSpecUrl: "https://example.test/directory-spec.yaml",
      appName: "jumpcloud",
      defaultTenantId: "default",
      defaultUserId: "default",
      vaultService: vault
    });

    const discovered = await client.listKnownEndpoints({ search: "systemusers" });
    assert.equal(discovered.count, 2);

    const ids = discovered.endpoints.map((entry) => entry.operationId);
    assert.ok(ids.includes("systemusers_list"));
    assert.ok(ids.includes("systemusers_update"));
  } finally {
    global.fetch = originalFetch;
  }
});

test("TargetServiceClient requestByOperation uses multi-user Vault token", async () => {
  const vault = createVaultMock();
  const { fetchMock, calls } = createFetchMock();
  const originalFetch = global.fetch;
  global.fetch = fetchMock;

  try {
    const client = new TargetServiceClient({
      consoleBaseUrl: "https://console.jumpcloud.com",
      directoryInsightsBaseUrl: "https://api.jumpcloud.com",
      consoleSpecUrl: "https://example.test/console-spec.yaml",
      directoryInsightsSpecUrl: "https://example.test/directory-spec.yaml",
      appName: "jumpcloud",
      defaultTenantId: "default",
      defaultUserId: "default",
      vaultService: vault
    });

    await client.upsertUserToken({
      tenantId: "tenant-a",
      userId: "team-a",
      tokenId: "primary",
      value: "api-key-1",
      tokenType: "apiKey",
      headerName: "x-api-key"
    });

    await client.setActiveUserToken({ tenantId: "tenant-a", userId: "team-a", tokenId: "primary" });

    const response = await client.requestByOperation({
      tenantId: "tenant-a",
      userId: "team-a",
      operationId: "systemusers_update",
      pathParams: { id: "abc123" },
      body: { firstname: "Alex" }
    });

    assert.equal(response.status, 200);

    const apiCall = calls.find((entry) => entry.url.includes("/api/systemusers/abc123"));
    assert.ok(apiCall);
    assert.equal(apiCall.options.method, "PUT");
    assert.equal(apiCall.options.headers["x-api-key"], "api-key-1");
  } finally {
    global.fetch = originalFetch;
  }
});
