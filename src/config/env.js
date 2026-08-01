import dotenv from "dotenv";

dotenv.config();

const TRANSPORT_MODES = new Set(["stdio", "http", "both"]);
const HTTP_AUTH_MODES = new Set(["token"]);

function enumValue(name, fallback, allowedValues) {
  const value = String(process.env[name] ?? fallback).toLowerCase();
  if (!allowedValues.has(value)) {
    throw new Error(
      `Environment variable ${name} must be one of: ${Array.from(allowedValues).join(", ")}`
    );
  }
  return value;
}

function required(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (value === undefined || value === "") {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function positiveNumber(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`Environment variable ${name} must be a non-negative number`);
  }
  return value;
}

function portNumber(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error(`Environment variable ${name} must be an integer between 1 and 65535`);
  }
  return value;
}

function parseCsv(name, fallback = "") {
  return String(process.env[name] ?? fallback)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function booleanValue(name, fallback = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") {
    return fallback;
  }

  const value = String(raw).toLowerCase();
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }

  throw new Error(`Environment variable ${name} must be either true or false`);
}

function normalizeAppName(value, fallback = "jumpcloud") {
  return String(value ?? fallback).trim().toLowerCase().replace(/[^a-z0-9_-]/g, "-") || fallback;
}

function optional(name, fallback = "") {
  const value = process.env[name];
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return String(value);
}

const transportMode = enumValue("MCP_TRANSPORT_MODE", "stdio", TRANSPORT_MODES);
const httpAuthMode = enumValue("MCP_HTTP_AUTH_MODE", "token", HTTP_AUTH_MODES);

export const env = {
  appName: normalizeAppName(process.env.APP_NAME, "jumpcloud"),
  mcpServerName: process.env.MCP_SERVER_NAME ?? "jumpcloud-mcp",
  mcpServerVersion: process.env.MCP_SERVER_VERSION ?? "0.1.0",
  adminAuthKey: process.env.MCP_ADMIN_AUTH_KEY ?? "",
  allowSensitiveOutput: booleanValue("MCP_ALLOW_SENSITIVE_OUTPUT", false),
  defaultUserId: optional("MCP_CONFIG_DEFAULT_USER_ID", "default").trim() || "default",
  jumpcloud: {
    timeoutMs: positiveNumber("JUMPCLOUD_TIMEOUT_MS", "20000"),
    consoleBaseUrl: required("JUMPCLOUD_CONSOLE_BASE_URL", "https://console.jumpcloud.com"),
    directoryInsightsBaseUrl: required("JUMPCLOUD_DIRECTORY_INSIGHTS_BASE_URL", "https://api.jumpcloud.com"),
    consoleSpecUrl: required("JUMPCLOUD_CONSOLE_SPEC_URL", "https://docs.jumpcloud.com/new/console/index.yaml"),
    directoryInsightsSpecUrl: required(
      "JUMPCLOUD_DIRECTORY_INSIGHTS_SPEC_URL",
      "https://docs.jumpcloud.com/new/api/insights/directory/index.yaml"
    )
  },
  postgres: {
    host: required("POSTGRES_HOST", "127.0.0.1"),
    port: portNumber("POSTGRES_PORT", "5432"),
    database: required("POSTGRES_DB", "mcp_config"),
    user: required("POSTGRES_USER", "mcp_user"),
    password: required("POSTGRES_PASSWORD", "mcp_password")
  },
  vault: {
    addr: required("VAULT_ADDR", "http://127.0.0.1:8200"),
    token: optional("VAULT_TOKEN", ""),
    agentEnabled: booleanValue("VAULT_AGENT_ENABLED", false),
    agentAuthMode: optional("VAULT_AGENT_AUTH_MODE", "file"),
    agentTokenFilePath: optional("VAULT_AGENT_TOKEN_FILE_PATH", ""),
    agentListenerEnabled: booleanValue("VAULT_AGENT_LISTENER_ENABLED", false),
    agentListenerAddr: optional("VAULT_AGENT_LISTENER_ADDR", "http://127.0.0.1:8100"),
    kvMount: required("VAULT_KV_MOUNT", "secret"),
    writeRetryAttempts: positiveNumber("VAULT_WRITE_RETRY_ATTEMPTS", "3"),
    writeRetryBaseDelayMs: positiveNumber("VAULT_WRITE_RETRY_BASE_DELAY_MS", "200"),
    writeRetryMaxDelayMs: positiveNumber("VAULT_WRITE_RETRY_MAX_DELAY_MS", "2000")
  },
  transport: {
    mode: transportMode,
    http: {
      host: required("MCP_HTTP_HOST", "127.0.0.1"),
      port: portNumber("MCP_HTTP_PORT", "3000"),
      mcpPath: required("MCP_HTTP_PATH", "/mcp"),
      healthPath: required("MCP_HTTP_HEALTH_PATH", "/healthz"),
      authMode: httpAuthMode,
      authTokens: parseCsv("MCP_HTTP_AUTH_TOKENS", "replace-me-token"),
      trustedProxy: booleanValue("MCP_HTTP_TRUST_PROXY", false),
      allowedOrigins: parseCsv("MCP_HTTP_ALLOWED_ORIGINS", ""),
      allowedIps: parseCsv("MCP_HTTP_ALLOWED_IPS", ""),
      maxBodyBytes: positiveNumber("MCP_HTTP_MAX_BODY_BYTES", "1048576"),
      rateLimitWindowMs: positiveNumber("MCP_HTTP_RATE_LIMIT_WINDOW_MS", "60000"),
      rateLimitMaxRequests: positiveNumber("MCP_HTTP_RATE_LIMIT_MAX_REQUESTS", "60"),
      tokenSource: optional("MCP_HTTP_TOKEN_SOURCE", "vault").toLowerCase(),
      vaultTokenIndexPath: optional("MCP_HTTP_VAULT_TOKEN_INDEX_PATH", ""),
      vaultTokenDefaultUserId: optional("MCP_HTTP_VAULT_TOKEN_DEFAULT_USER_ID", "default"),
      vaultTokenRequiredScopes: parseCsv("MCP_HTTP_VAULT_TOKEN_REQUIRED_SCOPES", ""),
      vaultTokenRequiredAudience: optional("MCP_HTTP_VAULT_TOKEN_REQUIRED_AUDIENCE", ""),
      vaultTokenCacheTtlMs: positiveNumber("MCP_HTTP_VAULT_TOKEN_CACHE_TTL_MS", "30000"),
      oauth2IntrospectionUrl: optional("MCP_HTTP_OAUTH2_INTROSPECTION_URL", ""),
      oauth2ClientId: optional("MCP_HTTP_OAUTH2_CLIENT_ID", ""),
      oauth2ClientSecret: optional("MCP_HTTP_OAUTH2_CLIENT_SECRET", ""),
      oauth2RequiredScopes: parseCsv("MCP_HTTP_OAUTH2_REQUIRED_SCOPES", ""),
      oauth2RequiredAudience: optional("MCP_HTTP_OAUTH2_REQUIRED_AUDIENCE", ""),
      oauth2TimeoutMs: positiveNumber("MCP_HTTP_OAUTH2_TIMEOUT_MS", "5000"),
      oauth2CacheTtlMs: positiveNumber("MCP_HTTP_OAUTH2_CACHE_TTL_MS", "30000"),
      tls: {
        enabled: booleanValue("MCP_HTTP_TLS_ENABLED", false),
        certPath: process.env.MCP_HTTP_TLS_CERT_PATH ?? "",
        keyPath: process.env.MCP_HTTP_TLS_KEY_PATH ?? ""
      }
    }
  }
};
