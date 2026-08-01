import { env } from "../config/env.js";
import { getVaultUserTokenIndexPath } from "../config/vaultAuthTokenIndex.js";
import { createOAuth2IntrospectionVerifier } from "./oauth2.js";
import { createHttpMcpServer } from "./server.js";
import { createVaultTokenVerifier } from "./vaultTokenAuth.js";
import { createMcpServer } from "../mcp/server.js";
import { ConfigStore } from "../services/configStore.js";
import { TargetServiceClient } from "../services/targetService.js";
import { VaultService } from "../services/vault.js";

async function main() {
  if (env.transport.http.tls.enabled) {
    throw new Error(
      "MCP_HTTP_TLS_ENABLED=true is not supported in this process mode. Terminate TLS at a reverse proxy/load balancer."
    );
  }

  const configStore = new ConfigStore(env.postgres, {
    appName: env.appName,
    defaultUserId: env.defaultUserId
  });

  const vaultService = new VaultService({
    endpoint: env.vault.addr,
    token: env.vault.token,
    agentEnabled: env.vault.agentEnabled,
    agentAuthMode: env.vault.agentAuthMode,
    agentTokenFilePath: env.vault.agentTokenFilePath,
    agentListenerEnabled: env.vault.agentListenerEnabled,
    agentListenerAddr: env.vault.agentListenerAddr,
    kvMount: env.vault.kvMount,
    writeRetryAttempts: env.vault.writeRetryAttempts,
    writeRetryBaseDelayMs: env.vault.writeRetryBaseDelayMs,
    writeRetryMaxDelayMs: env.vault.writeRetryMaxDelayMs
  });

  const targetServiceClient = new TargetServiceClient({
    consoleBaseUrl: env.jumpcloud.consoleBaseUrl,
    directoryInsightsBaseUrl: env.jumpcloud.directoryInsightsBaseUrl,
    timeoutMs: env.jumpcloud.timeoutMs,
    consoleSpecUrl: env.jumpcloud.consoleSpecUrl,
    directoryInsightsSpecUrl: env.jumpcloud.directoryInsightsSpecUrl,
    appName: env.appName,
    defaultUserId: env.defaultUserId,
    vaultService
  });

  const tokenVerifier =
    env.transport.http.authMode === "token" || env.transport.http.authMode === "both"
      ? createVaultTokenVerifier({
          vaultService,
          indexPath:
            env.transport.http.vaultTokenIndexPath ||
            getVaultUserTokenIndexPath(env.appName, env.transport.http.vaultTokenDefaultUserId),
          defaultUserId: env.transport.http.vaultTokenDefaultUserId,
          requiredScopes: env.transport.http.vaultTokenRequiredScopes,
          requiredAudience: env.transport.http.vaultTokenRequiredAudience,
          cacheTtlMs: env.transport.http.vaultTokenCacheTtlMs
        })
      : null;

  const oauth2Verifier =
    env.transport.http.authMode === "oauth2" || env.transport.http.authMode === "both"
      ? createOAuth2IntrospectionVerifier({
          introspectionUrl: env.transport.http.oauth2IntrospectionUrl,
          clientId: env.transport.http.oauth2ClientId,
          clientSecret: env.transport.http.oauth2ClientSecret,
          requiredScopes: env.transport.http.oauth2RequiredScopes,
          requiredAudience: env.transport.http.oauth2RequiredAudience,
          timeoutMs: env.transport.http.oauth2TimeoutMs,
          cacheTtlMs: env.transport.http.oauth2CacheTtlMs
        })
      : null;

  const httpServer = createHttpMcpServer({
    host: env.transport.http.host,
    port: env.transport.http.port,
    mcpPath: env.transport.http.mcpPath,
    healthPath: env.transport.http.healthPath,
    authMode: env.transport.http.authMode,
    authTokens: env.transport.http.authTokens,
    tokenVerifier,
    oauth2Verifier,
    trustedProxy: env.transport.http.trustedProxy,
    allowedOrigins: env.transport.http.allowedOrigins,
    allowedIps: env.transport.http.allowedIps,
    maxBodyBytes: env.transport.http.maxBodyBytes,
    rateLimitWindowMs: env.transport.http.rateLimitWindowMs,
    rateLimitMaxRequests: env.transport.http.rateLimitMaxRequests,
    createMcpServer: () =>
      createMcpServer({
        name: env.mcpServerName,
        version: env.mcpServerVersion,
        serviceClient: targetServiceClient,
        configStore,
        allowSensitiveOutput: env.allowSensitiveOutput,
        appName: env.appName,
        defaultUserId: env.defaultUserId
      })
  });

  await httpServer.start();

  console.log(
    `HTTP MCP server listening on http://${httpServer.host}:${httpServer.port}${httpServer.mcpPath}`
  );

  const shutdown = async () => {
    await configStore.close();
    await httpServer.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  console.error("HTTP MCP server failed to start", error);
  process.exit(1);
});
