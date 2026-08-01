import { load as parseYaml } from "js-yaml";

const DEFAULT_TIMEOUT_MS = 20000;
const OPERATION_METHODS = ["get", "post", "put", "patch", "delete", "options", "head"];

function normalizeDomain(value) {
  const raw = String(value ?? "console").trim().toLowerCase();
  if (raw === "directory" || raw === "directory-insights" || raw === "insights") {
    return "directory-insights";
  }
  return "console";
}

function normalizePath(path) {
  const raw = String(path ?? "").trim();
  if (!raw) {
    return "/";
  }
  return raw.startsWith("/") ? raw : `/${raw}`;
}

function normalizeMethod(method) {
  return String(method ?? "GET").trim().toUpperCase();
}

function parseResponseBody(contentType, text) {
  if (!text) {
    return null;
  }

  if (String(contentType).includes("application/json")) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  return text;
}

function buildUrl(baseUrl, path, query) {
  const url = new URL(normalizePath(path), baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
  if (query && typeof query === "object") {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null) {
        continue;
      }
      url.searchParams.set(key, String(value));
    }
  }
  return url;
}

function compileTemplate(pathTemplate) {
  const keys = [];
  const escaped = pathTemplate
    .replace(/[-/\\^$+?.()|[\]{}]/g, "\\$&")
    .replace(/\{([a-zA-Z0-9_]+)\}/g, (_, key) => {
      keys.push(key);
      return "([^/]+)";
    });
  const regex = new RegExp(`^${escaped}$`);
  return { regex, keys };
}

function buildRequestPath(pathTemplate, pathParams = {}) {
  return pathTemplate.replace(/\{([a-zA-Z0-9_]+)\}/g, (_, key) => {
    const value = pathParams[key];
    if (value === undefined || value === null || value === "") {
      throw new Error(`Missing required path parameter: ${key}`);
    }
    return encodeURIComponent(String(value));
  });
}

function isMutatingMethod(method) {
  return ["POST", "PUT", "PATCH", "DELETE"].includes(normalizeMethod(method));
}

function resolveSecurityType(operation) {
  const security = Array.isArray(operation.security) ? operation.security : [];
  if (security.length === 0) {
    return "none";
  }

  const first = security[0];
  const names = Object.keys(first ?? {});
  if (names.some((name) => name.toLowerCase().includes("bearer"))) {
    return "bearer";
  }
  return "apiKey";
}

function normalizeTokenPayload(payload) {
  if (!payload || typeof payload !== "object") {
    return {
      activeTokenId: null,
      tokens: {}
    };
  }

  const tokens = payload.tokens && typeof payload.tokens === "object" ? payload.tokens : {};
  return {
    activeTokenId: payload.activeTokenId ?? null,
    tokens
  };
}

export class TargetServiceClient {
  constructor({
    consoleBaseUrl,
    directoryInsightsBaseUrl,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    consoleSpecUrl,
    directoryInsightsSpecUrl,
    appName,
    defaultTenantId,
    defaultUserId,
    vaultService
  }) {
    this.consoleBaseUrl = String(consoleBaseUrl ?? "https://console.jumpcloud.com").trim();
    this.directoryInsightsBaseUrl = String(directoryInsightsBaseUrl ?? "https://api.jumpcloud.com").trim();
    this.timeoutMs = Number(timeoutMs) > 0 ? Number(timeoutMs) : DEFAULT_TIMEOUT_MS;
    this.consoleSpecUrl = String(consoleSpecUrl ?? "").trim();
    this.directoryInsightsSpecUrl = String(directoryInsightsSpecUrl ?? "").trim();
    this.appName = String(appName ?? "jumpcloud").trim() || "jumpcloud";
    this.defaultTenantId = String(defaultTenantId ?? "default").trim() || "default";
    this.defaultUserId = String(defaultUserId ?? "default").trim() || "default";
    this.vaultService = vaultService;

    this.specCache = null;
  }

  getConnectionInfo() {
    return {
      consoleBaseUrl: this.consoleBaseUrl,
      directoryInsightsBaseUrl: this.directoryInsightsBaseUrl,
      timeoutMs: this.timeoutMs,
      consoleSpecUrl: this.consoleSpecUrl,
      directoryInsightsSpecUrl: this.directoryInsightsSpecUrl,
      tokenStorage: {
        provider: "vault",
        scope: "multi-tenant-user",
        vaultKvPrefix: `${this.appName}/tenants/:tenantId/users/:userId/jumpcloud/tokens`
      }
    };
  }

  resolveScope(tenantId, userId) {
    const resolvedTenantId = String(tenantId ?? this.defaultTenantId).trim() || this.defaultTenantId;
    const resolvedUserId = String(userId ?? this.defaultUserId).trim() || this.defaultUserId;
    return {
      tenantId: resolvedTenantId,
      userId: resolvedUserId
    };
  }

  getUserTokenPath(tenantId, userId) {
    const scope = this.resolveScope(tenantId, userId);
    return `${this.appName}/tenants/${scope.tenantId}/users/${scope.userId}/jumpcloud/tokens`;
  }

  getTenantTokenPrefix(tenantId) {
    const scope = this.resolveScope(tenantId);
    return `${this.appName}/tenants/${scope.tenantId}/users`;
  }

  async listTenantUsersWithTokens(tenantId) {
    const scope = this.resolveScope(tenantId);
    const prefix = this.getTenantTokenPrefix(scope.tenantId);

    try {
      const entries = await this.vaultService.listSecrets(prefix);
      return entries
        .map((entry) => String(entry).replace(/\/$/, "").trim())
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b));
    } catch {
      return [];
    }
  }

  async getUserTokens(tenantId, userId, { includeSensitive = false } = {}) {
    const scope = this.resolveScope(tenantId, userId);
    const path = this.getUserTokenPath(scope.tenantId, scope.userId);
    const payload = normalizeTokenPayload(await this.vaultService.getSecret(path));

    if (includeSensitive) {
      return {
        tenantId: scope.tenantId,
        userId: scope.userId,
        ...payload
      };
    }

    const redactedTokens = {};
    for (const [tokenId, tokenEntry] of Object.entries(payload.tokens)) {
      redactedTokens[tokenId] = {
        ...tokenEntry,
        value: tokenEntry?.value ? "[REDACTED]" : null
      };
    }

    return {
      tenantId: scope.tenantId,
      userId: scope.userId,
      activeTokenId: payload.activeTokenId,
      tokens: redactedTokens
    };
  }

  async upsertUserToken({
    tenantId,
    userId,
    tokenId,
    value,
    tokenType = "apiKey",
    headerName = "x-api-key",
    description = ""
  }) {
    const scope = this.resolveScope(tenantId, userId);
    const effectiveTokenId = String(tokenId ?? "").trim();
    if (!effectiveTokenId) {
      throw new Error("tokenId is required");
    }

    const tokenValue = String(value ?? "").trim();
    if (!tokenValue) {
      throw new Error("value is required");
    }

    const effectiveTokenType = String(tokenType ?? "apiKey").trim() || "apiKey";
    const effectiveHeaderName = String(headerName ?? "x-api-key").trim() || "x-api-key";

    const path = this.getUserTokenPath(scope.tenantId, scope.userId);
    const payload = normalizeTokenPayload(await this.vaultService.getSecret(path));
    const existing = payload.tokens[effectiveTokenId] ?? {};

    payload.tokens[effectiveTokenId] = {
      ...existing,
      tokenId: effectiveTokenId,
      tokenType: effectiveTokenType,
      headerName: effectiveTokenType === "bearer" ? "authorization" : effectiveHeaderName,
      description: String(description ?? "").trim(),
      active: true,
      value: tokenValue,
      updatedAt: new Date().toISOString(),
      createdAt: existing.createdAt ?? new Date().toISOString()
    };

    if (!payload.activeTokenId) {
      payload.activeTokenId = effectiveTokenId;
    }

    await this.vaultService.setSecret(path, payload);

    return {
      tenantId: scope.tenantId,
      userId: scope.userId,
      tokenId: effectiveTokenId,
      activeTokenId: payload.activeTokenId
    };
  }

  async setActiveUserToken({ tenantId, userId, tokenId }) {
    const scope = this.resolveScope(tenantId, userId);
    const effectiveTokenId = String(tokenId ?? "").trim();
    if (!effectiveTokenId) {
      throw new Error("tokenId is required");
    }

    const path = this.getUserTokenPath(scope.tenantId, scope.userId);
    const payload = normalizeTokenPayload(await this.vaultService.getSecret(path));
    if (!payload.tokens[effectiveTokenId]) {
      throw new Error(
        `Token not found for scope '${scope.tenantId}/${scope.userId}': ${effectiveTokenId}`
      );
    }

    payload.activeTokenId = effectiveTokenId;
    await this.vaultService.setSecret(path, payload);

    return {
      tenantId: scope.tenantId,
      userId: scope.userId,
      activeTokenId: effectiveTokenId
    };
  }

  async deleteUserToken({ tenantId, userId, tokenId }) {
    const scope = this.resolveScope(tenantId, userId);
    const effectiveTokenId = String(tokenId ?? "").trim();
    if (!effectiveTokenId) {
      throw new Error("tokenId is required");
    }

    const path = this.getUserTokenPath(scope.tenantId, scope.userId);
    const payload = normalizeTokenPayload(await this.vaultService.getSecret(path));
    delete payload.tokens[effectiveTokenId];

    if (payload.activeTokenId === effectiveTokenId) {
      payload.activeTokenId = Object.keys(payload.tokens)[0] ?? null;
    }

    await this.vaultService.setSecret(path, payload);

    return {
      tenantId: scope.tenantId,
      userId: scope.userId,
      activeTokenId: payload.activeTokenId,
      remainingTokenCount: Object.keys(payload.tokens).length
    };
  }

  async resolveTokenForRequest(tenantId, userId, tokenId = "") {
    const scope = this.resolveScope(tenantId, userId);
    const payload = normalizeTokenPayload(
      await this.vaultService.getSecret(this.getUserTokenPath(scope.tenantId, scope.userId))
    );
    const resolvedTokenId = String(tokenId ?? "").trim() || payload.activeTokenId;

    if (!resolvedTokenId || !payload.tokens[resolvedTokenId]) {
      throw new Error(
        `No active JumpCloud token configured for scope '${scope.tenantId}/${scope.userId}'. Use jumpcloud_user_token_upsert first.`
      );
    }

    const tokenEntry = payload.tokens[resolvedTokenId];
    if (tokenEntry.active === false) {
      throw new Error(`Configured token is inactive: ${resolvedTokenId}`);
    }

    const tokenValue = String(tokenEntry.value ?? "").trim();
    if (!tokenValue) {
      throw new Error(`Configured token has no value: ${resolvedTokenId}`);
    }

    return {
      tokenId: resolvedTokenId,
      tokenType: String(tokenEntry.tokenType ?? "apiKey").trim() || "apiKey",
      headerName: String(tokenEntry.headerName ?? "x-api-key").trim() || "x-api-key",
      value: tokenValue
    };
  }

  async loadSpec(url) {
    const response = await fetch(url, { headers: { Accept: "application/yaml, text/yaml, text/plain" } });
    if (!response.ok) {
      throw new Error(`Failed to load OpenAPI spec: ${url} (${response.status})`);
    }
    const raw = await response.text();
    return parseYaml(raw);
  }

  async ensureSpecCache() {
    if (this.specCache) {
      return this.specCache;
    }

    const [consoleSpec, directorySpec] = await Promise.all([
      this.loadSpec(this.consoleSpecUrl),
      this.loadSpec(this.directoryInsightsSpecUrl)
    ]);

    const operations = [];

    const addSpecOperations = (domain, spec, fallbackBaseUrl) => {
      const servers = Array.isArray(spec?.servers) ? spec.servers : [];
      const defaultBaseUrl = String(servers[0]?.url ?? fallbackBaseUrl);
      const paths = spec?.paths && typeof spec.paths === "object" ? spec.paths : {};

      for (const [path, pathItem] of Object.entries(paths)) {
        if (!pathItem || typeof pathItem !== "object") {
          continue;
        }

        for (const methodName of OPERATION_METHODS) {
          const operation = pathItem[methodName];
          if (!operation || typeof operation !== "object") {
            continue;
          }

          const method = methodName.toUpperCase();
          const operationId =
            operation.operationId ??
            `${domain}.${method.toLowerCase()}_${path.replace(/[{}\/]/g, "_").replace(/_+/g, "_")}`;
          const tags = Array.isArray(operation.tags) ? operation.tags : [];
          const summary = operation.summary ?? operation.description ?? "";

          operations.push({
            domain,
            method,
            pathTemplate: path,
            operationId,
            tags,
            summary,
            baseUrl: defaultBaseUrl,
            securityType: resolveSecurityType(operation),
            pathMatcher: compileTemplate(path)
          });
        }
      }
    };

    addSpecOperations("console", consoleSpec, this.consoleBaseUrl);
    addSpecOperations("directory-insights", directorySpec, this.directoryInsightsBaseUrl);

    this.specCache = {
      loadedAt: new Date().toISOString(),
      operations,
      totals: {
        all: operations.length,
        console: operations.filter((op) => op.domain === "console").length,
        directoryInsights: operations.filter((op) => op.domain === "directory-insights").length
      }
    };

    return this.specCache;
  }

  async listKnownEndpoints({ domain, search, limit = 200 } = {}) {
    const cache = await this.ensureSpecCache();
    const normalizedDomain = domain ? normalizeDomain(domain) : "";
    const normalizedSearch = String(search ?? "").trim().toLowerCase();

    let filtered = cache.operations;

    if (normalizedDomain) {
      filtered = filtered.filter((op) => op.domain === normalizedDomain);
    }

    if (normalizedSearch) {
      filtered = filtered.filter((op) => {
        return (
          op.operationId.toLowerCase().includes(normalizedSearch) ||
          op.pathTemplate.toLowerCase().includes(normalizedSearch) ||
          op.method.toLowerCase().includes(normalizedSearch) ||
          op.tags.some((tag) => String(tag).toLowerCase().includes(normalizedSearch)) ||
          String(op.summary).toLowerCase().includes(normalizedSearch)
        );
      });
    }

    return {
      loadedAt: cache.loadedAt,
      totalDiscovered: cache.totals,
      count: Math.min(filtered.length, limit),
      endpoints: filtered.slice(0, limit).map((op) => ({
        domain: op.domain,
        operationId: op.operationId,
        method: op.method,
        path: op.pathTemplate,
        tags: op.tags,
        summary: op.summary,
        securityType: op.securityType
      }))
    };
  }

  async request({
    tenantId,
    userId,
    tokenId,
    domain,
    method = "GET",
    path = "/",
    query,
    body,
    headers = {}
  }) {
    const normalizedMethod = normalizeMethod(method);
    const normalizedPath = normalizePath(path);
    const normalizedDomain = domain ? normalizeDomain(domain) : "console";

    const baseUrl = normalizedDomain === "directory-insights" ? this.directoryInsightsBaseUrl : this.consoleBaseUrl;
    const url = buildUrl(baseUrl, normalizedPath, query);

    const token = await this.resolveTokenForRequest(tenantId, userId, tokenId);

    const requestHeaders = {
      Accept: "application/json, text/plain, application/yaml, text/yaml",
      ...headers
    };

    if (token.tokenType === "bearer") {
      requestHeaders.Authorization = `Bearer ${token.value}`;
    } else {
      requestHeaders[token.headerName] = token.value;
    }

    let payload;
    if (body !== undefined && body !== null && normalizedMethod !== "GET") {
      if (typeof body === "string") {
        payload = body;
      } else {
        payload = JSON.stringify(body);
        if (!requestHeaders["Content-Type"] && !requestHeaders["content-type"]) {
          requestHeaders["Content-Type"] = "application/json";
        }
      }
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        method: normalizedMethod,
        headers: requestHeaders,
        body: payload,
        signal: controller.signal
      });

      const text = await response.text();
      const contentType = String(response.headers.get("content-type") ?? "");
      const parsed = parseResponseBody(contentType, text);

      if (!response.ok) {
        const error = new Error(`JumpCloud request failed: ${normalizedMethod} ${url.pathname} -> ${response.status}`);
        error.status = response.status;
        error.response = parsed;
        throw error;
      }

      return {
        domain: normalizedDomain,
        tokenId: token.tokenId,
        method: normalizedMethod,
        path: url.pathname,
        url: url.toString(),
        status: response.status,
        contentType,
        data: parsed
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async requestByOperation({
    tenantId,
    userId,
    tokenId,
    operationId,
    pathParams,
    query,
    body,
    headers
  }) {
    const cache = await this.ensureSpecCache();
    const op = cache.operations.find((candidate) => candidate.operationId === operationId);
    if (!op) {
      throw new Error(`Unknown operationId: ${operationId}`);
    }

    const resolvedPath = buildRequestPath(op.pathTemplate, pathParams);

    return this.request({
      tenantId,
      userId,
      tokenId,
      domain: op.domain,
      method: op.method,
      path: resolvedPath,
      query,
      body,
      headers
    });
  }

  async getOperationById(operationId) {
    const cache = await this.ensureSpecCache();
    return cache.operations.find((candidate) => candidate.operationId === operationId) ?? null;
  }

  async healthCheck(tenantId, userId, tokenId) {
    return this.request({
      tenantId,
      userId,
      tokenId,
      domain: "console",
      method: "GET",
      path: "/api/systemusers"
    });
  }

  async suggestOperations({ intent, method, path, domain }) {
    const cache = await this.ensureSpecCache();
    const normalizedIntent = String(intent ?? "").toLowerCase();
    const normalizedMethod = method ? normalizeMethod(method).toLowerCase() : "";
    const normalizedPath = path ? normalizePath(path).toLowerCase() : "";
    const normalizedDomain = domain ? normalizeDomain(domain) : "";

    let ranked = cache.operations;

    if (normalizedDomain) {
      ranked = ranked.filter((op) => op.domain === normalizedDomain);
    }

    if (normalizedMethod) {
      ranked = ranked.filter((op) => op.method.toLowerCase() === normalizedMethod);
    }

    if (normalizedPath) {
      ranked = ranked.filter((op) => op.pathTemplate.toLowerCase().includes(normalizedPath));
    }

    if (normalizedIntent) {
      const terms = normalizedIntent.split(/[^a-z0-9]+/).filter(Boolean);
      ranked = ranked
        .map((op) => {
          const searchable = `${op.operationId} ${op.pathTemplate} ${op.tags.join(" ")} ${op.summary}`.toLowerCase();
          const score = terms.reduce((acc, term) => acc + (searchable.includes(term) ? 1 : 0), 0);
          return { op, score };
        })
        .filter((entry) => entry.score > 0)
        .sort((a, b) => b.score - a.score)
        .map((entry) => entry.op);
    }

    return ranked.slice(0, 12).map((op) => ({
      operationId: op.operationId,
      domain: op.domain,
      method: op.method,
      path: op.pathTemplate,
      tags: op.tags,
      summary: op.summary,
      isMutating: isMutatingMethod(op.method)
    }));
  }

  isMutatingMethod(method) {
    return isMutatingMethod(method);
  }
}
