const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.PG_CONNECTION_STRING || '';

function parseDbConfig() {
  let connStr = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.PG_CONNECTION_STRING || '';
  connStr = connStr.trim().replace(/^["']|["']$/g, '');

  let config = {};

  if (connStr.startsWith('postgres://') || connStr.startsWith('postgresql://')) {
    // Regex matches postgres://user:password@host:port/database splitting on the LAST @
    const match = connStr.match(/^postgres(?:ql)?:\/\/([^:]+):(.*)@([^:/]+)(?::(\d+))?\/([^?]+)(?:\?.*)?$/);
    if (match) {
      const [, user, rawPassword, host, port, database] = match;
      let password = rawPassword;
      while (typeof password === 'string' && password.includes('%')) {
        try {
          const d = decodeURIComponent(password);
          if (d === password) break;
          password = d;
        } catch (e) {
          break;
        }
      }
      config = {
        user: decodeURIComponent(user),
        password: password,
        host: host,
        port: port ? Number(port) : 5432,
        database: database
      };
    } else {
      config = { connectionString: connStr };
    }
  } else if (connStr) {
    config = { connectionString: connStr };
  }

  // Fallback to individual environment variables if present
  if (!config.host && process.env.host) config.host = process.env.host;
  if (!config.port && process.env.port) config.port = Number(process.env.port) || 5432;
  if (!config.database && process.env.database) config.database = process.env.database;
  if (!config.user && process.env.user) config.user = process.env.user;

  return config;
}

let pool = null;
let schemaInitialized = false;

function getPool() {
  if (!pool) {
    const dbConfig = parseDbConfig();
    const hasConfig = dbConfig.connectionString || (dbConfig.host && dbConfig.database);
    if (hasConfig) {
      pool = new Pool({
        ...dbConfig,
        ssl: process.env.PG_SSL === 'false' ? false : { rejectUnauthorized: false },
        max: Number(process.env.PG_MAX_CONNECTIONS) || 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 8000,
      });

      pool.on('error', (err) => {
        console.error('[PostgreSQL Pool Error]:', err.message);
      });
    }
  }
  return pool;
}

/**
 * Health check to verify PostgreSQL connectivity
 */
async function checkPostgresHealth() {
  const p = getPool();
  if (!p) {
    return { available: false, error: 'DATABASE_URL is not configured' };
  }
  try {
    const res = await p.query('SELECT 1 as alive');
    return { available: res.rows?.[0]?.alive === 1 };
  } catch (err) {
    return { available: false, error: err.message };
  }
}

/**
 * Executes a function within a strict PostgreSQL ACID transaction
 */
async function withTransaction(callback) {
  const p = getPool();
  if (!p) {
    throw new Error('POSTGRESQL_UNAVAILABLE: DATABASE_URL is not configured.');
  }

  const client = await p.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rbErr) {
      console.error('[PostgreSQL Rollback Error]:', rbErr.message);
    }
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Initialize relational and event tables with indexes and constraints
 */
async function initSchema() {
  const p = getPool();
  if (!p) return false;
  if (schemaInitialized) return true;

  const client = await p.connect();
  try {
    await client.query(`
      -- STAGE 1: CREATE ALL TABLES WITHOUT INDEXES OR CONSTRAINTS
      CREATE TABLE IF NOT EXISTS cloud_organizations (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) UNIQUE NOT NULL,
          org_name VARCHAR(255) NOT NULL,
          license_key VARCHAR(128),
          status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
          created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_stores (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT',
          store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01',
          store_token VARCHAR(64) UNIQUE NOT NULL,
          store_name VARCHAR(255) NOT NULL,
          product_key VARCHAR(64),
          status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
          created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_devices (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT',
          store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01',
          device_id VARCHAR(64) NOT NULL,
          machine_id VARCHAR(128) NOT NULL,
          device_key VARCHAR(255) NOT NULL,
          status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
          created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
          last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_pairings (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          pairing_token VARCHAR(64) UNIQUE NOT NULL,
          org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT',
          store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01',
          device_id VARCHAR(64) NOT NULL DEFAULT 'POS-01',
          device_key VARCHAR(255),
          status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
          created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
          expires_at TIMESTAMPTZ,
          last_used_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_events (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT',
          store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01',
          store_token VARCHAR(64) NOT NULL,
          device_id VARCHAR(64) NOT NULL,
          event_id VARCHAR(128) NOT NULL,
          event_type VARCHAR(64) NOT NULL,
          entity_type VARCHAR(64) NOT NULL,
          entity_id VARCHAR(128) NOT NULL,
          sequence_number BIGINT NOT NULL,
          payload JSONB NOT NULL,
          received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
          processed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_shifts (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT',
          store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01',
          store_token VARCHAR(64) NOT NULL,
          device_id VARCHAR(64) NOT NULL,
          shift_id_local VARCHAR(128) NOT NULL,
          shift_number INT NOT NULL,
          cashier_id VARCHAR(128),
          cashier_name VARCHAR(255),
          opening_cash_cents BIGINT NOT NULL DEFAULT 0,
          expected_cash_cents BIGINT NOT NULL DEFAULT 0,
          actual_cash_cents BIGINT NOT NULL DEFAULT 0,
          difference_cents BIGINT NOT NULL DEFAULT 0,
          total_sales_cents BIGINT NOT NULL DEFAULT 0,
          total_returns_cents BIGINT NOT NULL DEFAULT 0,
          status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
          opened_at TIMESTAMPTZ NOT NULL,
          closed_at TIMESTAMPTZ,
          synced_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_invoices (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT',
          store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01',
          store_token VARCHAR(64) NOT NULL,
          device_id VARCHAR(64) NOT NULL,
          invoice_id_local VARCHAR(128) NOT NULL,
          invoice_number VARCHAR(128) NOT NULL,
          shift_id_local VARCHAR(128),
          cashier_name VARCHAR(255),
          customer_id VARCHAR(128),
          customer_name VARCHAR(255) DEFAULT 'عميل نقدي',
          subtotal_cents BIGINT NOT NULL,
          discount_cents BIGINT NOT NULL DEFAULT 0,
          final_amount_cents BIGINT NOT NULL,
          paid_amount_cents BIGINT NOT NULL,
          change_amount_cents BIGINT NOT NULL DEFAULT 0,
          payment_method VARCHAR(32) NOT NULL DEFAULT 'cash',
          status VARCHAR(32) NOT NULL DEFAULT 'COMPLETED',
          created_at TIMESTAMPTZ NOT NULL,
          synced_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_invoice_items (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT',
          store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01',
          store_token VARCHAR(64) NOT NULL,
          device_id VARCHAR(64) NOT NULL,
          invoice_id_local VARCHAR(128) NOT NULL,
          product_id VARCHAR(128) NOT NULL,
          product_name VARCHAR(255) NOT NULL,
          barcode VARCHAR(128),
          unit_cost_cents BIGINT NOT NULL DEFAULT 0,
          unit_price_cents BIGINT NOT NULL,
          quantity NUMERIC(12, 3) NOT NULL,
          subtotal_cents BIGINT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL
      );

      CREATE TABLE IF NOT EXISTS cloud_inventory_movements (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT',
          store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01',
          store_token VARCHAR(64) NOT NULL,
          device_id VARCHAR(64) NOT NULL,
          movement_id_local VARCHAR(128) NOT NULL,
          product_id VARCHAR(128) NOT NULL,
          movement_type VARCHAR(64) NOT NULL,
          change_quantity NUMERIC(12, 3) NOT NULL,
          reference_id VARCHAR(128),
          created_at TIMESTAMPTZ NOT NULL
      );

      CREATE TABLE IF NOT EXISTS cloud_cash_movements (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT',
          store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01',
          store_token VARCHAR(64) NOT NULL,
          device_id VARCHAR(64) NOT NULL,
          movement_id_local VARCHAR(128) NOT NULL,
          shift_id_local VARCHAR(128),
          movement_type VARCHAR(32) NOT NULL,
          amount_cents BIGINT NOT NULL,
          reason TEXT,
          created_by VARCHAR(255),
          created_at TIMESTAMPTZ NOT NULL
      );

      CREATE TABLE IF NOT EXISTS cloud_products (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT',
          store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01',
          store_token VARCHAR(64) NOT NULL,
          device_id VARCHAR(64) NOT NULL,
          product_id_local VARCHAR(128) NOT NULL,
          name VARCHAR(255) NOT NULL,
          barcode VARCHAR(128),
          sku VARCHAR(128),
          cost_price_cents BIGINT NOT NULL DEFAULT 0,
          selling_price_cents BIGINT NOT NULL DEFAULT 0,
          stock_quantity NUMERIC(12, 3) NOT NULL DEFAULT 0,
          min_stock_alert NUMERIC(12, 3) NOT NULL DEFAULT 5,
          unit VARCHAR(64) DEFAULT 'قطعة',
          is_active INT NOT NULL DEFAULT 1,
          created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_device_sequences (
          store_token VARCHAR(64) NOT NULL,
          device_id VARCHAR(64) NOT NULL,
          last_sequence_number BIGINT NOT NULL DEFAULT 0,
          last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (store_token, device_id)
      );

      CREATE TABLE IF NOT EXISTS executed_operations_ledger (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT',
          store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01',
          device_id VARCHAR(64) NOT NULL,
          idempotency_key VARCHAR(255) NOT NULL,
          operation_type VARCHAR(64) NOT NULL,
          entity_id VARCHAR(128),
          financial_delta_cents BIGINT DEFAULT 0,
          inventory_delta NUMERIC(12, 3) DEFAULT 0,
          response_payload JSONB,
          executed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_users (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL,
          email VARCHAR(255) NOT NULL,
          username VARCHAR(100),
          password_hash VARCHAR(255) NOT NULL,
          full_name VARCHAR(150) NOT NULL,
          role VARCHAR(50) NOT NULL,
          status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
          failed_login_attempts INT NOT NULL DEFAULT 0,
          locked_until TIMESTAMPTZ,
          last_login_at TIMESTAMPTZ,
          password_changed_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_user_store_access (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          org_id VARCHAR(64) NOT NULL,
          user_id UUID NOT NULL,
          store_id VARCHAR(64) NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_user_sessions (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          session_id VARCHAR(100) UNIQUE NOT NULL,
          user_id UUID NOT NULL,
          org_id VARCHAR(64) NOT NULL,
          refresh_token_hash VARCHAR(255) NOT NULL,
          user_agent TEXT,
          ip_address VARCHAR(64),
          revoked_at TIMESTAMPTZ,
          revoked_reason VARCHAR(100),
          expires_at TIMESTAMPTZ NOT NULL,
          last_seen_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
          created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cloud_audit_logs (
          id BIGSERIAL PRIMARY KEY,
          org_id VARCHAR(64) NOT NULL,
          store_id VARCHAR(64),
          device_id VARCHAR(64),
          actor_id VARCHAR(100) NOT NULL,
          actor_type VARCHAR(50) NOT NULL,
          action VARCHAR(100) NOT NULL,
          resource_type VARCHAR(100) NOT NULL,
          resource_id VARCHAR(100),
          correlation_id VARCHAR(100),
          details JSONB NOT NULL DEFAULT '{}'::jsonb,
          ip_address VARCHAR(64),
          user_agent TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      -- STAGE 2: ENSURE ALL COLUMNS EXIST FOR LEGACY TABLES
      ALTER TABLE cloud_organizations ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE';
      ALTER TABLE cloud_stores ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';
      ALTER TABLE cloud_stores ADD COLUMN IF NOT EXISTS store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01';
      ALTER TABLE cloud_stores ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE';
      ALTER TABLE cloud_devices ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';
      ALTER TABLE cloud_devices ADD COLUMN IF NOT EXISTS store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01';
      ALTER TABLE cloud_pairings ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';
      ALTER TABLE cloud_pairings ADD COLUMN IF NOT EXISTS store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01';
      ALTER TABLE cloud_events ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';
      ALTER TABLE cloud_events ADD COLUMN IF NOT EXISTS store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01';
      ALTER TABLE cloud_shifts ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';
      ALTER TABLE cloud_shifts ADD COLUMN IF NOT EXISTS store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01';
      ALTER TABLE cloud_invoices ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';
      ALTER TABLE cloud_invoices ADD COLUMN IF NOT EXISTS store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01';
      ALTER TABLE cloud_invoice_items ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';
      ALTER TABLE cloud_invoice_items ADD COLUMN IF NOT EXISTS store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01';
      ALTER TABLE cloud_inventory_movements ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';
      ALTER TABLE cloud_inventory_movements ADD COLUMN IF NOT EXISTS store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01';
      ALTER TABLE cloud_cash_movements ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';
      ALTER TABLE cloud_cash_movements ADD COLUMN IF NOT EXISTS store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01';
      ALTER TABLE cloud_products ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';
      ALTER TABLE cloud_products ADD COLUMN IF NOT EXISTS store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01';
      ALTER TABLE executed_operations_ledger ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';
      ALTER TABLE executed_operations_ledger ADD COLUMN IF NOT EXISTS store_id VARCHAR(64) NOT NULL DEFAULT 'STORE-01';
      ALTER TABLE cloud_user_store_access ADD COLUMN IF NOT EXISTS org_id VARCHAR(64) NOT NULL DEFAULT 'ORG-DEFAULT';

      -- STAGE 3: CREATE INDEXES SAFELY NOW THAT ALL TABLES AND COLUMNS EXIST
      CREATE INDEX IF NOT EXISTS idx_cloud_orgs_id ON cloud_organizations(org_id);
      CREATE INDEX IF NOT EXISTS idx_cloud_stores_token ON cloud_stores(store_token);
      CREATE INDEX IF NOT EXISTS idx_cloud_stores_org_store ON cloud_stores(org_id, store_id);
      CREATE INDEX IF NOT EXISTS idx_cloud_devices_lookup ON cloud_devices(org_id, store_id, device_id);
      CREATE INDEX IF NOT EXISTS idx_cloud_pairings_token ON cloud_pairings(pairing_token, status);
      CREATE INDEX IF NOT EXISTS idx_cloud_events_store_seq ON cloud_events(store_token, device_id, sequence_number ASC);
      CREATE INDEX IF NOT EXISTS idx_cloud_events_org_store ON cloud_events(org_id, store_id, event_type);
      CREATE INDEX IF NOT EXISTS idx_cloud_shifts_lookup ON cloud_shifts(store_token, status, opened_at DESC);
      CREATE INDEX IF NOT EXISTS idx_cloud_invoices_store_date ON cloud_invoices(store_token, created_at DESC);

      -- STAGE 4: IDEMPOTENT CONSTRAINTS & UNIQUE INDEXES
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_cloud_stores_org_store') THEN
          ALTER TABLE cloud_stores ADD CONSTRAINT uq_cloud_stores_org_store UNIQUE (org_id, store_id);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_store_device_binding') THEN
          ALTER TABLE cloud_devices ADD CONSTRAINT uq_store_device_binding UNIQUE (org_id, store_id, device_id);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_store_device_event') THEN
          ALTER TABLE cloud_events ADD CONSTRAINT uq_store_device_event UNIQUE (store_token, device_id, event_id);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_store_device_shift') THEN
          ALTER TABLE cloud_shifts ADD CONSTRAINT uq_store_device_shift UNIQUE (store_token, device_id, shift_id_local);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_store_invoice_id') THEN
          ALTER TABLE cloud_invoices ADD CONSTRAINT uq_store_invoice_id UNIQUE (store_token, invoice_id_local);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_cloud_invoice_line') THEN
          ALTER TABLE cloud_invoice_items ADD CONSTRAINT uq_cloud_invoice_line UNIQUE (store_token, invoice_id_local, product_id);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_cloud_inv_movement') THEN
          ALTER TABLE cloud_inventory_movements ADD CONSTRAINT uq_cloud_inv_movement UNIQUE (store_token, movement_id_local);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_cloud_cash_movement') THEN
          ALTER TABLE cloud_cash_movements ADD CONSTRAINT uq_cloud_cash_movement UNIQUE (store_token, device_id, movement_id_local);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_store_product_id') THEN
          ALTER TABLE cloud_products ADD CONSTRAINT uq_store_product_id UNIQUE (store_token, product_id_local);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_org_idempotency_key') THEN
          ALTER TABLE executed_operations_ledger ADD CONSTRAINT uq_org_idempotency_key UNIQUE (org_id, idempotency_key);
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_rules WHERE rulename = 'no_update_cloud_audit') THEN
          CREATE RULE no_update_cloud_audit AS ON UPDATE TO cloud_audit_logs DO INSTEAD NOTHING;
        END IF;

        IF NOT EXISTS (SELECT 1 FROM pg_rules WHERE rulename = 'no_delete_cloud_audit') THEN
          CREATE RULE no_delete_cloud_audit AS ON DELETE TO cloud_audit_logs DO INSTEAD NOTHING;
        END IF;
      END $$;
    `);
    schemaInitialized = true;
    return true;
  } catch (err) {
    console.error('[PostgreSQL Schema Init Error]:', err.message);
    return false;
  } finally {
    client.release();
  }
}

module.exports = {
  getPool,
  withTransaction,
  initSchema,
  checkPostgresHealth,
  DATABASE_URL,
};
