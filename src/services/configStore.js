import pg from "pg";

const { Pool } = pg;

function normalizeIdentifier(value, fallback) {
  const candidate = String(value ?? fallback).trim().toLowerCase().replace(/[^a-z0-9_]/g, "_");
  if (!candidate || !/^[a-z][a-z0-9_]*$/.test(candidate)) {
    throw new Error(`Invalid Postgres table name: ${value}`);
  }

  return candidate;
}

function normalizeAppName(value, fallback = "jumpcloud") {
  const candidate = String(value ?? fallback).trim().toLowerCase().replace(/[^a-z0-9_-]/g, "_");
  if (!candidate || !/^[a-z][a-z0-9_]*$/.test(candidate)) {
    return fallback;
  }

  return candidate;
}

export class ConfigStore {
  constructor(postgresConfig, options = {}) {
    this.pool = new Pool(postgresConfig);
    this.appName = normalizeAppName(options.appName ?? process.env.APP_NAME, "jumpcloud");
    this.defaultTenantId = String(options.defaultTenantId ?? "default").trim() || "default";
    this.defaultUserId = String(options.defaultUserId ?? "default").trim() || "default";
    this.tableName = normalizeIdentifier(options.tableName ?? `${this.appName}_config`, `${this.appName}_config`);
  }

  normalizeScope(tenantId, userId) {
    const resolvedTenantId = String(tenantId ?? this.defaultTenantId).trim() || this.defaultTenantId;
    const resolvedUserId = String(userId ?? this.defaultUserId).trim() || this.defaultUserId;
    return {
      tenantId: resolvedTenantId,
      userId: resolvedUserId,
      scopeId: `${resolvedTenantId}/${resolvedUserId}`
    };
  }

  async healthcheck() {
    await this.pool.query("SELECT 1");
    return { ok: true };
  }

  async listConfigs(prefix, tenantId, userId) {
    const scope = this.normalizeScope(tenantId, userId);
    const hasPrefix = Boolean(prefix && prefix.trim());
    const result = hasPrefix
      ? await this.pool.query(
          `SELECT user_id, key, value, updated_at FROM ${this.tableName} WHERE user_id = $1 AND key ILIKE $2 ORDER BY key ASC`,
          [scope.scopeId, `${prefix}%`]
        )
      : await this.pool.query(
          `SELECT user_id, key, value, updated_at FROM ${this.tableName} WHERE user_id = $1 ORDER BY key ASC`,
          [scope.scopeId]
        );

    return result.rows.map((row) => {
      const [tenantPart = scope.tenantId, userPart = scope.userId] = String(row.user_id).split("/");
      return {
        ...row,
        tenant_id: tenantPart,
        scoped_user_id: userPart
      };
    });
  }

  async getConfig(key, tenantId, userId) {
    const scope = this.normalizeScope(tenantId, userId);
    const result = await this.pool.query(
      `SELECT user_id, key, value, updated_at FROM ${this.tableName} WHERE user_id = $1 AND key = $2`,
      [scope.scopeId, key]
    );

    const row = result.rows[0] ?? null;
    if (!row) {
      return null;
    }
    const [tenantPart = scope.tenantId, userPart = scope.userId] = String(row.user_id).split("/");
    return {
      ...row,
      tenant_id: tenantPart,
      scoped_user_id: userPart
    };
  }

  async setConfig(key, value, tenantId, userId) {
    const scope = this.normalizeScope(tenantId, userId);
    const result = await this.pool.query(
      `
      INSERT INTO ${this.tableName} (user_id, key, value, updated_at)
      VALUES ($1, $2, $3::jsonb, NOW())
      ON CONFLICT (user_id, key)
      DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
      RETURNING user_id, key, value, updated_at
      `,
      [scope.scopeId, key, JSON.stringify(value)]
    );

    const row = result.rows[0];
    return {
      ...row,
      tenant_id: scope.tenantId,
      scoped_user_id: scope.userId
    };
  }

  async deleteConfig(key, tenantId, userId) {
    const scope = this.normalizeScope(tenantId, userId);
    const result = await this.pool.query(`DELETE FROM ${this.tableName} WHERE user_id = $1 AND key = $2`, [
      scope.scopeId,
      key
    ]);
    return result.rowCount > 0;
  }

  async getTokenRotationIntervalMs({ userId, userIntervalConfigKey, defaultIntervalMs }) {
    const scope = this.normalizeScope(undefined, userId);
    const scopedConfig = await this.getConfig(userIntervalConfigKey, scope.tenantId, scope.userId);
    const scopedValue = Number(scopedConfig?.value);
    if (Number.isFinite(scopedValue) && scopedValue > 0) {
      return {
        intervalMs: scopedValue,
        source: "user",
        userId: scope.userId,
        tenantId: scope.tenantId,
        key: userIntervalConfigKey
      };
    }

    const defaultScopedConfig = await this.getConfig(
      userIntervalConfigKey,
      this.defaultTenantId,
      this.defaultUserId
    );
    const defaultScopedValue = Number(defaultScopedConfig?.value);
    if (Number.isFinite(defaultScopedValue) && defaultScopedValue > 0) {
      return {
        intervalMs: defaultScopedValue,
        source: "default-user",
        userId: this.defaultUserId,
        tenantId: this.defaultTenantId,
        key: userIntervalConfigKey
      };
    }

    return {
      intervalMs: defaultIntervalMs,
      source: "env-default",
      userId: this.defaultUserId,
      tenantId: this.defaultTenantId,
      key: userIntervalConfigKey
    };
  }

  async close() {
    await this.pool.end();
  }
}
