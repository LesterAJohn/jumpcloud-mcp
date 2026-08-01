#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { env } from "../src/config/env.js";
import { TargetServiceClient } from "../src/services/targetService.js";

function createNoopVaultService() {
  return {
    async getSecret() {
      return null;
    },
    async setSecret() {
      return { ok: true };
    }
  };
}

function sortOperations(operations) {
  return [...operations].sort((a, b) => {
    const domain = String(a.domain).localeCompare(String(b.domain));
    if (domain !== 0) {
      return domain;
    }

    const path = String(a.pathTemplate).localeCompare(String(b.pathTemplate));
    if (path !== 0) {
      return path;
    }

    const method = String(a.method).localeCompare(String(b.method));
    if (method !== 0) {
      return method;
    }

    return String(a.operationId).localeCompare(String(b.operationId));
  });
}

function summarizeByKey(items, keyName) {
  const counts = new Map();
  for (const item of items) {
    const key = String(item[keyName] ?? "unknown");
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  return Array.from(counts.entries())
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

function summarizeTopTags(operations, limit = 20) {
  const counts = new Map();
  for (const op of operations) {
    const tags = Array.isArray(op.tags) && op.tags.length > 0 ? op.tags : ["untagged"];
    for (const tag of tags) {
      const key = String(tag);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
  }

  return Array.from(counts.entries())
    .map(([tag, count]) => ({ tag, count }))
    .sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag))
    .slice(0, limit);
}

function buildMarkdown(payload) {
  const lines = [];
  lines.push("# JumpCloud OpenAPI Endpoint Inventory");
  lines.push("");
  lines.push(`Generated at: ${payload.generatedAt}`);
  lines.push("");
  lines.push("## Sources");
  lines.push("");
  lines.push(`- Console spec: ${payload.sources.consoleSpecUrl}`);
  lines.push(`- Directory Insights spec: ${payload.sources.directoryInsightsSpecUrl}`);
  lines.push("");
  lines.push("## Totals");
  lines.push("");
  lines.push(`- All operations: ${payload.totals.all}`);
  lines.push(`- Console operations: ${payload.totals.console}`);
  lines.push(`- Directory Insights operations: ${payload.totals.directoryInsights}`);
  lines.push(`- Fingerprint: ${payload.fingerprint}`);
  lines.push("");
  lines.push("## By Method");
  lines.push("");
  for (const row of payload.summary.byMethod) {
    lines.push(`- ${row.key}: ${row.count}`);
  }
  lines.push("");
  lines.push("## Top Tags");
  lines.push("");
  for (const row of payload.summary.topTags) {
    lines.push(`- ${row.tag}: ${row.count}`);
  }
  lines.push("");
  lines.push("## Notes");
  lines.push("");
  lines.push("- Full operation records are in docs/openapi-endpoint-inventory.json.");
  lines.push("- Use npm run inventory:check in CI to detect inventory drift.");
  lines.push("");

  return `${lines.join("\n")}\n`;
}

async function main() {
  const client = new TargetServiceClient({
    consoleBaseUrl: env.jumpcloud.consoleBaseUrl,
    directoryInsightsBaseUrl: env.jumpcloud.directoryInsightsBaseUrl,
    timeoutMs: env.jumpcloud.timeoutMs,
    consoleSpecUrl: env.jumpcloud.consoleSpecUrl,
    directoryInsightsSpecUrl: env.jumpcloud.directoryInsightsSpecUrl,
    appName: env.appName,
    defaultUserId: env.defaultUserId,
    vaultService: createNoopVaultService()
  });

  const cache = await client.ensureSpecCache();
  const operations = sortOperations(cache.operations).map((op) => ({
    domain: op.domain,
    method: op.method,
    path: op.pathTemplate,
    operationId: op.operationId,
    tags: op.tags,
    summary: op.summary,
    securityType: op.securityType
  }));

  const fingerprint = createHash("sha256").update(JSON.stringify(operations)).digest("hex");

  const payload = {
    generatedAt: new Date().toISOString(),
    sources: {
      consoleSpecUrl: env.jumpcloud.consoleSpecUrl,
      directoryInsightsSpecUrl: env.jumpcloud.directoryInsightsSpecUrl
    },
    totals: {
      all: operations.length,
      console: operations.filter((op) => op.domain === "console").length,
      directoryInsights: operations.filter((op) => op.domain === "directory-insights").length
    },
    fingerprint,
    summary: {
      byMethod: summarizeByKey(operations, "method"),
      byDomain: summarizeByKey(operations, "domain"),
      topTags: summarizeTopTags(operations)
    },
    operations
  };

  const outputDir = "docs";
  await mkdir(outputDir, { recursive: true });

  await writeFile(`${outputDir}/openapi-endpoint-inventory.json`, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  await writeFile(`${outputDir}/openapi-endpoint-inventory.md`, buildMarkdown(payload), "utf8");

  process.stdout.write(
    `Generated inventory with ${payload.totals.all} operations. Fingerprint: ${payload.fingerprint}\n`
  );
}

main().catch((error) => {
  process.stderr.write(`[inventory][error] ${error?.stack ?? error?.message ?? String(error)}\n`);
  process.exit(1);
});
