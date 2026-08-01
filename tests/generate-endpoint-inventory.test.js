import assert from "node:assert/strict";
import test from "node:test";

import { resolveGeneratedAt } from "../scripts/generate-endpoint-inventory.js";

test("resolveGeneratedAt preserves the existing timestamp when inventory content is unchanged", () => {
  const existingPayload = {
    generatedAt: "2026-08-01T02:35:47.323Z",
    sources: {
      consoleSpecUrl: "https://example.test/console.yaml",
      directoryInsightsSpecUrl: "https://example.test/directory.yaml"
    },
    totals: {
      all: 2,
      console: 1,
      directoryInsights: 1
    },
    fingerprint: "abc123",
    summary: {
      byMethod: [{ key: "GET", count: 1 }],
      byDomain: [{ key: "console", count: 1 }],
      topTags: [{ tag: "Users", count: 1 }]
    },
    operations: [{ domain: "console", method: "GET", path: "/users", operationId: "users_list" }]
  };

  const { generatedAt: _generatedAt, ...nextPayload } = existingPayload;

  assert.equal(
    resolveGeneratedAt(existingPayload, nextPayload, "2026-08-01T02:38:14.706Z"),
    "2026-08-01T02:35:47.323Z"
  );
});

test("resolveGeneratedAt uses a fresh timestamp when inventory content changes", () => {
  const existingPayload = {
    generatedAt: "2026-08-01T02:35:47.323Z",
    fingerprint: "abc123",
    totals: {
      all: 1
    },
    summary: {
      byMethod: [],
      byDomain: [],
      topTags: []
    },
    operations: []
  };

  const nextPayload = {
    fingerprint: "def456",
    totals: {
      all: 2
    },
    summary: {
      byMethod: [],
      byDomain: [],
      topTags: []
    },
    operations: [{ operationId: "new_operation" }]
  };

  assert.equal(
    resolveGeneratedAt(existingPayload, nextPayload, "2026-08-01T02:38:14.706Z"),
    "2026-08-01T02:38:14.706Z"
  );
});
