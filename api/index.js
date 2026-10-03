const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { Redis } = require('@upstash/redis');
const db = require('./db');
const auth = require('./auth');
const rbac = require('./rbac');
const storeScope = require('./storeScope');
const userOrgScope = require('./userOrgScope');
const deviceScope = require('./deviceScope');
const pairingScope = require('./pairingScope');
const analyticsScope = require('./analyticsScope');
const onboardingService = require('./services/onboardingService');

const PRIVATE_KEY_PATH = path.resolve(__dirname, '../keys/private_key.pem');

function getPrivateKey() {
  if (process.env.RSA_PRIVATE_KEY) {
    return process.env.RSA_PRIVATE_KEY.replace(/\\n/g, '\n');
  }
  if (fs.existsSync(PRIVATE_KEY_PATH)) {
    return fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
  }
  throw new Error('RSA_PRIVATE_KEY is not set. Please configure env variable RSA_PRIVATE_KEY.');
}

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

let redis = null;
if (UPSTASH_URL && UPSTASH_TOKEN) {
  try {
    redis = new Redis({
      url: UPSTASH_URL,
      token: UPSTASH_TOKEN,
    });
  } catch (e) {
    console.warn('[Upstash Redis Init Warning]:', e.message);
  }
}

// Distributed / In-Memory Sliding Window Rate Limiter for Login (FINDING-PROD-02)
const loginRateLimitStore = new Map();
const LOGIN_RATE_LIMIT_WINDOW_SECONDS = 60;
const LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 10;

async function checkLoginRateLimit(rawIp) {
  const cleanIp = (String(rawIp || '127.0.0.1')).split(',')[0].trim();
  const key = `ratelimit:login:${cleanIp}`;
  const now = Date.now();

  if (redis) {
    try {
      const current = await redis.incr(key);
      if (current === 1) {
        await redis.expire(key, LOGIN_RATE_LIMIT_WINDOW_SECONDS);
      }
      if (current > LOGIN_RATE_LIMIT_MAX_ATTEMPTS) {
        const ttl = await redis.ttl(key);
        return { allowed: false, retryAfterSeconds: Math.max(1, ttl || LOGIN_RATE_LIMIT_WINDOW_SECONDS) };
      }
      return { allowed: true };
    } catch (err) {
      console.warn('[Redis RateLimit Warning]:', err.message);
    }
  }

  // In-memory sliding window fallback
  let record = loginRateLimitStore.get(cleanIp);
  if (!record || (now - record.windowStart) > (LOGIN_RATE_LIMIT_WINDOW_SECONDS * 1000)) {
    record = { windowStart: now, count: 1 };
    loginRateLimitStore.set(cleanIp, record);
    return { allowed: true };
  }

  record.count++;
  if (record.count > LOGIN_RATE_LIMIT_MAX_ATTEMPTS) {
    const retryAfterSeconds = Math.max(1, Math.ceil((record.windowStart + (LOGIN_RATE_LIMIT_WINDOW_SECONDS * 1000) - now) / 1000));
    return { allowed: false, retryAfterSeconds };
  }

  return { allowed: true };
}

// In-memory stores
let memoryStore = [];
let productKeysStore = [];
let auditStore = [];
let cloudSnapshots = new Map();
let deviceSnapshots = new Map();
let idempotencyStore = new Set();
let deviceSequenceStore = new Map();

async function isIdempotencyProcessed(token, deviceId, key) {
  if (!key) return false;
  const fullKey = `idem:${token}:${deviceId || 'default'}:${key}`;
  try {
    if (redis) {
      const exists = await redis.get(fullKey);
      if (exists) return true;
    }
  } catch (e) {
    console.warn('[Redis Idempotency Check Warning]:', e.message);
  }
  return idempotencyStore.has(fullKey);
}

async function markIdempotencyProcessed(token, deviceId, key) {
  if (!key) return;
  const fullKey = `idem:${token}:${deviceId || 'default'}:${key}`;
  idempotencyStore.add(fullKey);
  try {
    if (redis) {
      await redis.set(fullKey, '1', { ex: 604800 }); // 7 days TTL
    }
  } catch (e) {
    console.warn('[Redis Idempotency Set Warning]:', e.message);
  }
}

async function getDeviceSequence(token, deviceId) {
  const seqKey = `seq:${token}:${deviceId || 'default'}`;
  try {
    if (redis) {
      const val = await redis.get(seqKey);
      if (val !== null && val !== undefined) return Number(val) || 0;
    }
  } catch {}
  return deviceSequenceStore.get(seqKey) || 0;
}

async function setDeviceSequence(token, deviceId, seq) {
  const seqKey = `seq:${token}:${deviceId || 'default'}`;
  deviceSequenceStore.set(seqKey, seq);
  try {
    if (redis) {
      await redis.set(seqKey, seq);
    }
  } catch {}
}

// Unified Single-Source-of-Truth Aggregator for Store Today Sales, Payment Methods & Profit
async function fetchStoreTodaySalesAggregation(pool, token, orgId, storeId, targetDate = null) {
  let whereClause = 'store_token = $1';
  const queryParams = [token];
  if (orgId && storeId) {
    whereClause = 'store_token = $1 AND org_id = $2 AND store_id = $3';
    queryParams.push(orgId, storeId);
  }

  let dateFilter = `created_at >= ((NOW() AT TIME ZONE 'Africa/Cairo')::date AT TIME ZONE 'Africa/Cairo') AND created_at < (((NOW() AT TIME ZONE 'Africa/Cairo')::date + INTERVAL '1 day') AT TIME ZONE 'Africa/Cairo')`;
  if (targetDate && typeof targetDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(targetDate.trim())) {
    const dParamIdx = queryParams.length + 1;
    queryParams.push(targetDate.trim());
    dateFilter = `created_at >= ($${dParamIdx}::date AT TIME ZONE 'Africa/Cairo') AND created_at < (($${dParamIdx}::date + INTERVAL '1 day') AT TIME ZONE 'Africa/Cairo')`;
  }

  const salesRes = await pool.query(`
    WITH today_invoices AS (
      SELECT 
        id,
        invoice_id_local,
        final_amount_cents,
        discount_cents,
        payment_method
      FROM cloud_invoices 
      WHERE ${whereClause} AND ${dateFilter} AND status = 'COMPLETED'
    ),
    invoice_item_profits AS (
      SELECT 
        cii.invoice_id_local,
        COALESCE(SUM(
          (cii.unit_price_cents - COALESCE(NULLIF(cii.unit_cost_cents, 0), CAST(cii.unit_price_cents * 0.70 AS BIGINT))) * cii.quantity
        ), 0)::bigint as invoice_profit_cents,
        COALESCE(SUM(
          COALESCE(NULLIF(cii.unit_cost_cents, 0), CAST(cii.unit_price_cents * 0.70 AS BIGINT)) * cii.quantity
        ), 0)::bigint as invoice_cogs_cents
      FROM cloud_invoice_items cii
      WHERE ${whereClause.replace(/store_token/g, 'cii.store_token').replace(/org_id/g, 'cii.org_id').replace(/store_id/g, 'cii.store_id')}
        AND cii.invoice_id_local IN (SELECT invoice_id_local FROM today_invoices)
      GROUP BY cii.invoice_id_local
    ),
    sales_summary AS (
      SELECT
        COUNT(ti.invoice_id_local)::int as invoices_count,
        COALESCE(SUM(ti.final_amount_cents), 0)::bigint as gross_sales_cents,
        COALESCE(SUM(ti.discount_cents), 0)::bigint as discount_cents,
        COALESCE(SUM(CASE WHEN LOWER(TRIM(ti.payment_method)) IN ('cash', 'نقدي', 'كاش') THEN ti.final_amount_cents ELSE 0 END), 0)::bigint as gross_cash_cents,
        COALESCE(SUM(CASE WHEN LOWER(TRIM(ti.payment_method)) IN ('card', 'بطاقة', 'فيزا', 'visa') THEN ti.final_amount_cents ELSE 0 END), 0)::bigint as card_cents,
        COALESCE(SUM(CASE WHEN LOWER(TRIM(ti.payment_method)) IN ('instapay', 'vodafone_cash', 'wallet', 'انستاباي', 'محفظة', 'فودافون كاش') THEN ti.final_amount_cents ELSE 0 END), 0)::bigint as instapay_cents,
        COALESCE(SUM(CASE WHEN LOWER(TRIM(ti.payment_method)) IN ('credit', 'آجل', 'اجل', 'على الحساب') THEN ti.final_amount_cents ELSE 0 END), 0)::bigint as credit_cents,
        COALESCE(SUM(p.invoice_cogs_cents), 0)::bigint as total_cogs_cents,
        COALESCE(SUM(p.invoice_profit_cents), 0)::bigint as net_profit_cents
      FROM today_invoices ti
      LEFT JOIN invoice_item_profits p ON ti.invoice_id_local = p.invoice_id_local
    ),
    returns_summary AS (
      SELECT
        COALESCE(SUM(amount_cents), 0)::bigint as total_return_cents
      FROM cloud_cash_movements
      WHERE ${whereClause} AND ${dateFilter} AND movement_type = 'RETURN'
    )
    SELECT 
      s.invoices_count,
      GREATEST(0, (s.gross_sales_cents - r.total_return_cents))::bigint as total_sales_cents,
      s.discount_cents,
      GREATEST(0, (s.gross_cash_cents - r.total_return_cents))::bigint as cash_cents,
      s.card_cents,
      s.instapay_cents,
      s.credit_cents,
      s.total_cogs_cents,
      GREATEST(0, (s.net_profit_cents - s.discount_cents))::bigint as net_profit_cents
    FROM sales_summary s
    CROSS JOIN returns_summary r
  `, queryParams);

  if (salesRes.rows && salesRes.rows.length > 0) {
    const row = salesRes.rows[0];
    const totalSalesCents = Number(row.total_sales_cents) || 0;
    const netProfitCents = Number(row.net_profit_cents) || 0;
    const profitMarginPct = totalSalesCents > 0 ? Math.round((netProfitCents / totalSalesCents) * 1000) / 10 : 0;

    return {
      invoicesCount: Number(row.invoices_count) || 0,
      totalSalesCents,
      cashCents: Number(row.cash_cents) || 0,
      cardCents: Number(row.card_cents) || 0,
      instapayCents: Number(row.instapay_cents) || 0,
      creditCents: Number(row.credit_cents) || 0,
      cogsCents: Number(row.total_cogs_cents) || 0,
      netProfitCents,
      profitMarginPct
    };
  }

  return {
    invoicesCount: 0,
    totalSalesCents: 0,
    cashCents: 0,
    cardCents: 0,
    instapayCents: 0,
    creditCents: 0,
    cogsCents: 0,
    netProfitCents: 0,
    profitMarginPct: 0
  };
}

// Shift-Scoped Aggregator for Store Sales, Payment Methods & Profit per Shift
async function fetchStoreShiftSalesAggregation(pool, token, orgId, storeId, shiftIdLocal) {
  if (!shiftIdLocal) {
    return fetchStoreTodaySalesAggregation(pool, token, orgId, storeId);
  }

  let whereClause = 'store_token = $1 AND shift_id_local = $2';
  const queryParams = [token, shiftIdLocal];
  if (orgId && storeId) {
    whereClause = 'store_token = $1 AND org_id = $2 AND store_id = $3 AND shift_id_local = $4';
    queryParams.push(orgId, storeId, shiftIdLocal);
  }

  const salesRes = await pool.query(`
    WITH shift_invoices AS (
      SELECT 
        id,
        invoice_id_local,
        final_amount_cents,
        discount_cents,
        payment_method
      FROM cloud_invoices 
      WHERE ${whereClause} AND status = 'COMPLETED'
    ),
    invoice_item_profits AS (
      SELECT 
        cii.invoice_id_local,
        COALESCE(SUM(
          (cii.unit_price_cents - COALESCE(NULLIF(cii.unit_cost_cents, 0), CAST(cii.unit_price_cents * 0.70 AS BIGINT))) * cii.quantity
        ), 0)::bigint as invoice_profit_cents,
        COALESCE(SUM(
          COALESCE(NULLIF(cii.unit_cost_cents, 0), CAST(cii.unit_price_cents * 0.70 AS BIGINT)) * cii.quantity
        ), 0)::bigint as invoice_cogs_cents
      FROM cloud_invoice_items cii
      WHERE ${whereClause.replace(/shift_id_local = \$[24]/g, '1=1').replace(/store_token/g, 'cii.store_token').replace(/org_id/g, 'cii.org_id').replace(/store_id/g, 'cii.store_id')}
        AND cii.invoice_id_local IN (SELECT invoice_id_local FROM shift_invoices)
      GROUP BY cii.invoice_id_local
    ),
    sales_summary AS (
      SELECT
        COUNT(ti.invoice_id_local)::int as invoices_count,
        COALESCE(SUM(ti.final_amount_cents), 0)::bigint as gross_sales_cents,
        COALESCE(SUM(ti.discount_cents), 0)::bigint as discount_cents,
        COALESCE(SUM(CASE WHEN LOWER(TRIM(ti.payment_method)) IN ('cash', 'نقدي', 'كاش') THEN ti.final_amount_cents ELSE 0 END), 0)::bigint as gross_cash_cents,
        COALESCE(SUM(CASE WHEN LOWER(TRIM(ti.payment_method)) IN ('card', 'بطاقة', 'فيزا', 'visa') THEN ti.final_amount_cents ELSE 0 END), 0)::bigint as card_cents,
        COALESCE(SUM(CASE WHEN LOWER(TRIM(ti.payment_method)) IN ('instapay', 'vodafone_cash', 'wallet', 'انستاباي', 'محفظة', 'فودافون كاش') THEN ti.final_amount_cents ELSE 0 END), 0)::bigint as instapay_cents,
        COALESCE(SUM(CASE WHEN LOWER(TRIM(ti.payment_method)) IN ('credit', 'آجل', 'اجل', 'على الحساب') THEN ti.final_amount_cents ELSE 0 END), 0)::bigint as credit_cents,
        COALESCE(SUM(p.invoice_cogs_cents), 0)::bigint as total_cogs_cents,
        COALESCE(SUM(p.invoice_profit_cents), 0)::bigint as net_profit_cents
      FROM shift_invoices ti
      LEFT JOIN invoice_item_profits p ON ti.invoice_id_local = p.invoice_id_local
    ),
    returns_summary AS (
      SELECT
        COALESCE(SUM(amount_cents), 0)::bigint as total_return_cents
      FROM cloud_cash_movements
      WHERE ${whereClause} AND movement_type = 'RETURN'
    )
    SELECT 
      s.invoices_count,
      GREATEST(0, (s.gross_sales_cents - r.total_return_cents))::bigint as total_sales_cents,
      s.discount_cents,
      GREATEST(0, (s.gross_cash_cents - r.total_return_cents))::bigint as cash_cents,
      s.card_cents,
      s.instapay_cents,
      s.credit_cents,
      s.total_cogs_cents,
      GREATEST(0, (s.net_profit_cents - s.discount_cents))::bigint as net_profit_cents
    FROM sales_summary s
    CROSS JOIN returns_summary r
  `, queryParams);

  if (salesRes.rows && salesRes.rows.length > 0) {
    const row = salesRes.rows[0];
    const totalSalesCents = Number(row.total_sales_cents) || 0;
    const netProfitCents = Number(row.net_profit_cents) || 0;
    const profitMarginPct = totalSalesCents > 0 ? Math.round((netProfitCents / totalSalesCents) * 1000) / 10 : 0;

    return {
      invoicesCount: Number(row.invoices_count) || 0,
      totalSalesCents,
      cashCents: Number(row.cash_cents) || 0,
      cardCents: Number(row.card_cents) || 0,
      instapayCents: Number(row.instapay_cents) || 0,
      creditCents: Number(row.credit_cents) || 0,
      cogsCents: Number(row.total_cogs_cents) || 0,
      netProfitCents,
      profitMarginPct
    };
  }

  return {
    invoicesCount: 0,
    totalSalesCents: 0,
    cashCents: 0,
    cardCents: 0,
    instapayCents: 0,
    creditCents: 0,
    cogsCents: 0,
    netProfitCents: 0,
    profitMarginPct: 0
  };
}

/**
 * Server-Side Authoritative Multi-Tenant Authentication & Resolution
 * Enforces hierarchy: LICENSE -> ORG/TENANT -> STORE -> DEVICE -> PAIRING -> SESSION
 * Rejects unauthorized, mismatched, or revoked tokens.
 */
async function resolveCloudTenantAuth(clientOrPool, { token, deviceId, deviceKey, machineId, isMobileReadOnly = false }) {
  if (!token || typeof token !== 'string' || !token.trim()) {
    return { authorized: false, status: 400, error: 'TOKEN_REQUIRED', code: 'INVALID_CREDENTIALS' };
  }
  const cleanToken = token.trim();
  const cleanDeviceId = (deviceId || 'POS-01').trim();
  const cleanDeviceKey = (deviceKey || '').trim();

  // 1. Check cloud_pairings & joined cloud_stores / cloud_organizations
  const pairingRes = await clientOrPool.query(`
    SELECT 
      p.id as pairing_id,
      p.pairing_token,
      p.org_id,
      p.store_id,
      p.device_id as bound_device_id,
      p.device_key as bound_device_key,
      p.status as pairing_status,
      p.expires_at,
      s.store_name,
      s.status as store_status,
      o.status as org_status
    FROM cloud_pairings p
    LEFT JOIN cloud_stores s ON (p.org_id = s.org_id AND p.store_id = s.store_id)
    LEFT JOIN cloud_organizations o ON (p.org_id = o.org_id)
    WHERE p.pairing_token = $1
    LIMIT 1
  `, [cleanToken]);

  let pairing = pairingRes.rows?.[0];

  // If pairing record doesn't exist yet, check cloud_stores or auto-register safely
  if (!pairing) {
    const storeRes = await clientOrPool.query(`
      SELECT s.*, o.status as org_status 
      FROM cloud_stores s
      LEFT JOIN cloud_organizations o ON (s.org_id = o.org_id)
      WHERE s.store_token = $1 LIMIT 1
    `, [cleanToken]);

    const store = storeRes.rows?.[0];
    if (store) {
      if (store.status !== 'ACTIVE' || (store.org_status && store.org_status !== 'ACTIVE')) {
        return { authorized: false, status: 403, error: 'STORE_OR_TENANT_INACTIVE', code: 'FORBIDDEN' };
      }
      const newPairing = await clientOrPool.query(`
        INSERT INTO cloud_pairings (pairing_token, org_id, store_id, device_id, device_key, status)
        VALUES ($1, $2, $3, $4, $5, 'ACTIVE')
        RETURNING *
      `, [cleanToken, store.org_id || 'ORG-DEFAULT', store.store_id || 'STORE-01', cleanDeviceId, cleanDeviceKey]);
      pairing = newPairing.rows?.[0];
    } else {
      // Auto-provision initial tenant, store and pairing in development mode ONLY
      const envStr = (process.env.NODE_ENV || process.env.VERCEL_ENV || process.env.APP_ENV || '').toLowerCase();
      const isProduction = envStr === 'production';

      if (!isProduction && cleanDeviceKey && !isMobileReadOnly) {
        const generatedOrgId = `ORG-${cleanToken.replace(/[^A-Za-z0-9]/g, '').substring(0, 10)}`;
        const generatedStoreId = 'STORE-01';
        await clientOrPool.query(`
          INSERT INTO cloud_organizations (org_id, org_name, status)
          VALUES ($1, 'مؤسسة أمان كاشير', 'ACTIVE')
          ON CONFLICT (org_id) DO NOTHING
        `, [generatedOrgId]);

        await clientOrPool.query(`
          INSERT INTO cloud_stores (org_id, store_id, store_token, store_name, status)
          VALUES ($1, $2, $3, 'أمان كاشير - الفرع الرئيسي', 'ACTIVE')
          ON CONFLICT (store_token) DO NOTHING
        `, [generatedOrgId, generatedStoreId, cleanToken]);

        const insPairing = await clientOrPool.query(`
          INSERT INTO cloud_pairings (pairing_token, org_id, store_id, device_id, device_key, status)
          VALUES ($1, $2, $3, $4, $5, 'ACTIVE')
          ON CONFLICT (pairing_token) DO UPDATE SET status = 'ACTIVE'
          RETURNING *
        `, [cleanToken, generatedOrgId, generatedStoreId, cleanDeviceId, cleanDeviceKey]);
        pairing = insPairing.rows?.[0];
      } else {
        return { authorized: false, status: 401, error: 'PAIRING_REQUIRED: Token is not paired. Please pair device before syncing.', code: 'PAIRING_REQUIRED' };
      }
    }
  }

  const pairingStatus = pairing.pairing_status || pairing.status || 'ACTIVE';
  const orgStatus = pairing.org_status || 'ACTIVE';
  const storeStatus = pairing.store_status || 'ACTIVE';
  const boundKey = pairing.bound_device_key || pairing.device_key;

  // 2. Validate Pairing & Organization Status
  if (pairingStatus !== 'ACTIVE' || orgStatus !== 'ACTIVE' || storeStatus !== 'ACTIVE') {
    return { authorized: false, status: 403, error: 'PAIRING_REVOKED_OR_INACTIVE', code: 'FORBIDDEN' };
  }

  if (pairing.expires_at && new Date(pairing.expires_at) < new Date()) {
    return { authorized: false, status: 403, error: 'PAIRING_EXPIRED', code: 'EXPIRED' };
  }

  // 3. For sync writes, verify device binding
  if (!isMobileReadOnly && boundKey) {
    if (cleanDeviceKey && cleanDeviceKey !== boundKey) {
      return { authorized: false, status: 401, error: 'DEVICE_KEY_MISMATCH_UNAUTHORIZED', code: 'DEVICE_UNAUTHORIZED' };
    }
  }

  return {
    authorized: true,
    orgId: pairing.org_id || 'ORG-DEFAULT',
    storeId: pairing.store_id || 'STORE-01',
    deviceId: cleanDeviceId,
    storeToken: cleanToken,
    storeName: pairing.store_name || 'أمان كاشير',
  };
}

async function getPersistedSnapshot(token, requestedShiftId = null) {
  const pool = db.getPool();
  let authContext = null;

  if (pool && token) {
    try {
      const auth = await resolveCloudTenantAuth(pool, { token, isMobileReadOnly: true });
      if (!auth.authorized) {
        return null;
      }
      authContext = auth;
    } catch (authErr) {
      console.warn('[Tenant Auth Check Error]:', authErr.message);
    }
  }

  try {
    if (redis && token && !requestedShiftId) {
      let snap = await redis.get(`snapshot:${token}`);
      if (Array.isArray(snap) && snap.length > 0) snap = snap[0];
      if (typeof snap === 'string') {
        try { snap = JSON.parse(snap); } catch {}
      }
      if (snap && typeof snap === 'object' && snap.snapshot) {
        const activeShift = snap.snapshot.current_shift || snap.snapshot.activeShift;
        if (pool && activeShift && activeShift.shift_id_local && (activeShift.status === 'OPEN' || activeShift.status_code === 'OPEN')) {
          try {
            const orgId = authContext?.orgId;
            const storeId = authContext?.storeId;
            const shiftAgg = await fetchStoreShiftSalesAggregation(pool, token, orgId, storeId, activeShift.shift_id_local);
            activeShift.shift_sales_cents = shiftAgg.totalSalesCents;
            activeShift.total_sales_cents = shiftAgg.totalSalesCents;
          } catch (sErr) {
            console.warn('[Redis Cached Shift Sales Aggregation Warning]:', sErr.message);
          }
        }
        return snap;
      }
    }
  } catch (e) {
    console.warn('[Redis Read Error]:', e.message);
  }

  // Durable Fallback: Reconstruct Snapshot directly from PostgreSQL Relational Tables
  try {
    if (pool && token) {
      const orgId = authContext?.orgId;
      const storeId = authContext?.storeId;

      let shiftWhere = 'store_token = $1 AND status = \'OPEN\'';
      let invWhere = 'store_token = $1';
      const qParams = [token];
      if (orgId && storeId) {
        shiftWhere = 'store_token = $1 AND org_id = $2 AND store_id = $3 AND status = \'OPEN\'';
        invWhere = 'store_token = $1 AND org_id = $2 AND store_id = $3';
        qParams.push(orgId, storeId);
      }

      const shiftRes = await pool.query(`
        SELECT * FROM cloud_shifts 
        WHERE ${shiftWhere}
        ORDER BY opened_at DESC LIMIT 1
      `, qParams);

      let activeShift = shiftRes.rows?.[0] ? { ...shiftRes.rows[0] } : null;
      if (activeShift && activeShift.shift_id_local) {
        try {
          const shiftAgg = await fetchStoreShiftSalesAggregation(pool, token, orgId, storeId, activeShift.shift_id_local);
          activeShift.shift_sales_cents = shiftAgg.totalSalesCents;
          activeShift.total_sales_cents = shiftAgg.totalSalesCents;
        } catch (sErr) {
          console.warn('[Shift Sales Aggregation Warning]:', sErr.message);
        }
      }

      const agg = requestedShiftId
        ? await fetchStoreShiftSalesAggregation(pool, token, orgId, storeId, requestedShiftId)
        : await fetchStoreTodaySalesAggregation(pool, token, orgId, storeId);

      const totalSalesCents = agg.totalSalesCents;
      const invoicesCount = agg.invoicesCount;
      const cashCents = agg.cashCents;
      const cardCents = agg.cardCents;
      const instapayCents = agg.instapayCents;
      const creditCents = agg.creditCents;
      const netProfitCents = agg.netProfitCents;
      const profitMarginPct = agg.profitMarginPct;
      const avgTicketCents = invoicesCount > 0 ? Math.round(totalSalesCents / invoicesCount) : 0;

      const invWhereWithShift = requestedShiftId
        ? `${invWhere} AND shift_id_local = $${qParams.length + 1}`
        : invWhere;
      const invParams = requestedShiftId ? [...qParams, requestedShiftId] : qParams;

      const recentInvRes = await pool.query(`
        SELECT invoice_id_local as id, invoice_number, cashier_name, customer_name, payment_method, final_amount_cents, created_at, device_id
        FROM cloud_invoices
        WHERE ${invWhereWithShift}
        ORDER BY created_at DESC, id DESC
        LIMIT 50
      `, invParams);

      const rebuiltSnapshot = {
        today: {
          total_sales: totalSalesCents / 100,
          total_sales_cents: totalSalesCents,
          invoices_count: invoicesCount,
          average_ticket: avgTicketCents / 100,
          average_ticket_cents: avgTicketCents,
          net_profit: netProfitCents / 100,
          net_profit_cents: netProfitCents,
          profit_margin: profitMarginPct,
          payment_methods: {
            cash: cashCents / 100,
            card: cardCents / 100,
            instapay: instapayCents / 100,
            credit: creditCents / 100,
          },
          payment_methods_cents: {
            cashCents,
            cardCents,
            instapayCents,
            creditCents,
          }
        },
        current_shift: activeShift,
        activeShift: activeShift,
        alerts: {
          low_stock_count: 0,
          pending_invoices_count: 0,
          active_devices_count: 1
        },
        salesSummary: {
          todayTotalCents: totalSalesCents,
          todayInvoiceCount: invoicesCount,
          averageInvoiceCents: avgTicketCents,
          netProfitCents: netProfitCents,
          profitMarginPct: profitMarginPct,
        },
        paymentBreakdown: {
          cashCents,
          cardCents,
          instapayCents,
          creditCents,
        },
        recentInvoices: recentInvRes.rows || [],
        lowStockProducts: [],
        last_sync: new Date().toLocaleTimeString('ar-EG', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      };

      const storeRec = {
        token,
        storeName: authContext?.storeName || 'أمان كاشير',
        machineId: 'POS-01',
        activeDevices: ['POS-01'],
        sequenceNumber: 100,
        snapshot: rebuiltSnapshot,
        lastSync: new Date().toISOString(),
        source: 'POSTGRESQL_RECONSTRUCTED'
      };

      if (redis) {
        try { await redis.set(`snapshot:${token}`, storeRec); } catch {}
      }
      cloudSnapshots.set(token, storeRec);
      return storeRec;
    }
  } catch (pgErr) {
    console.warn('[PostgreSQL Snapshot Reconstruction Warning]:', pgErr.message);
  }

  return cloudSnapshots.get(token) || null;
}


async function saveDeviceSnapshotAndAggregate(token, deviceId, deviceRecord) {
  const currentDevId = deviceId || 'POS-01';
  const devKey = `dev:${token}:${currentDevId}`;

  const existingDevRec = deviceSnapshots.get(devKey);
  const effectiveSnapshot = (deviceRecord.snapshot && Object.keys(deviceRecord.snapshot).length > 0) 
    ? deviceRecord.snapshot 
    : (existingDevRec?.snapshot || {});

  const mergedDeviceRecord = {
    ...deviceRecord,
    snapshot: effectiveSnapshot
  };
  deviceSnapshots.set(devKey, mergedDeviceRecord);

  // 1. Fetch durable state from PostgreSQL if pool exists
  const pool = db.getPool();
  let totalSalesCents = 0;
  let totalInvoicesCount = 0;
  let cashCents = 0;
  let cardCents = 0;
  let instapayCents = 0;
  let creditCents = 0;
  let pgNetProfitCents = null;
  let pgProfitMarginPct = null;
  let recentInvoices = [];
  let activeDevices = [currentDevId];
  let activeShift = null;

  if (pool) {
    try {
      const agg = await fetchStoreTodaySalesAggregation(pool, token);
      totalSalesCents = agg.totalSalesCents;
      totalInvoicesCount = agg.invoicesCount;
      cashCents = agg.cashCents;
      cardCents = agg.cardCents;
      instapayCents = agg.instapayCents;
      creditCents = agg.creditCents;
      pgNetProfitCents = agg.netProfitCents;
      pgProfitMarginPct = agg.profitMarginPct;

      // Recent 50 invoices from PostgreSQL
      const recentInvRes = await pool.query(`
        SELECT invoice_id_local as id, invoice_number, cashier_name, customer_name, payment_method, final_amount_cents, created_at, device_id
        FROM cloud_invoices
        WHERE store_token = $1
        ORDER BY created_at DESC, id DESC
        LIMIT 50
      `, [token]);
      recentInvoices = recentInvRes.rows || [];

      // Active devices in the last 15 minutes
      const activeDevRes = await pool.query(`
        SELECT DISTINCT device_id FROM cloud_device_sequences
        WHERE store_token = $1 AND last_seen_at >= NOW() - INTERVAL '15 minutes'
      `, [token]);
      if (activeDevRes.rows && activeDevRes.rows.length > 0) {
        activeDevices = activeDevRes.rows.map(r => r.device_id);
      } else {
        activeDevices = [currentDevId];
      }

      // Active Shift
      const shiftRes = await pool.query(`
        SELECT * FROM cloud_shifts 
        WHERE store_token = $1 AND status = 'OPEN' 
        ORDER BY opened_at DESC LIMIT 1
      `, [token]);
      if (shiftRes.rows && shiftRes.rows.length > 0) {
        activeShift = { ...shiftRes.rows[0] };
        if (activeShift.shift_id_local) {
          try {
            const shiftAgg = await fetchStoreShiftSalesAggregation(pool, token, activeShift.org_id, activeShift.store_id, activeShift.shift_id_local);
            activeShift.shift_sales_cents = shiftAgg.totalSalesCents;
            activeShift.total_sales_cents = shiftAgg.totalSalesCents;
          } catch (sErr) {
            console.warn('[Shift Sales Aggregation Warning]:', sErr.message);
          }
        }
      }
    } catch (pgErr) {
      console.warn('[PostgreSQL Aggregation Error - Falling back]:', pgErr.message);
    }
  }

  // Fallback if no PostgreSQL data found or pg not available -> Aggregate across all devices in store
  if (totalSalesCents === 0 && totalInvoicesCount === 0) {
    let combinedSalesCents = 0;
    let combinedInvoicesCount = 0;
    let combinedCashCents = 0;
    let combinedCardCents = 0;
    let combinedInstapayCents = 0;
    let combinedCreditCents = 0;
    const combinedRecentInvoices = [];
    const storeDevices = [];

    for (const [key, val] of deviceSnapshots.entries()) {
      if (key.startsWith(`dev:${token}:`) && val?.snapshot) {
        storeDevices.push(val.deviceId || key.split(':')[2]);
        const snapToday = val.snapshot.today || {};
        combinedSalesCents += Number(snapToday.total_sales_cents || (snapToday.total_sales ? snapToday.total_sales * 100 : 0)) || 0;
        combinedInvoicesCount += Number(snapToday.invoices_count || 0) || 0;
        const pm = snapToday.payment_methods_cents || snapToday.payment_methods || {};
        combinedCashCents += Number(pm.cashCents ?? (pm.cash ? pm.cash * 100 : 0)) || 0;
        combinedCardCents += Number(pm.cardCents ?? (pm.card ? pm.card * 100 : 0)) || 0;
        combinedInstapayCents += Number(pm.instapayCents ?? (pm.instapay ? pm.instapay * 100 : 0)) || 0;
        combinedCreditCents += Number(pm.creditCents ?? (pm.credit ? pm.credit * 100 : 0)) || 0;

        if (Array.isArray(val.snapshot.recentInvoices)) {
          combinedRecentInvoices.push(...val.snapshot.recentInvoices);
        }
      }
    }

    if (storeDevices.length > 0) {
      totalSalesCents = combinedSalesCents;
      totalInvoicesCount = combinedInvoicesCount;
      cashCents = combinedCashCents;
      cardCents = combinedCardCents;
      instapayCents = combinedInstapayCents;
      creditCents = combinedCreditCents;
      if (recentInvoices.length === 0 && combinedRecentInvoices.length > 0) {
        recentInvoices = combinedRecentInvoices.slice(0, 10);
      }
      if (activeDevices.length <= 1 && storeDevices.length > 1) {
        activeDevices = Array.from(new Set(storeDevices));
      }
    } else if (deviceRecord?.snapshot?.today?.total_sales_cents) {
      totalSalesCents = Number(deviceRecord.snapshot.today.total_sales_cents) || 0;
      totalInvoicesCount = Number(deviceRecord.snapshot.today.invoices_count) || 0;
      const pm = deviceRecord.snapshot.today.payment_methods_cents || {};
      cashCents = Number(pm.cashCents) || 0;
      cardCents = Number(pm.cardCents) || 0;
      instapayCents = Number(pm.instapayCents) || 0;
      creditCents = Number(pm.creditCents) || 0;
    }
  }
  if (recentInvoices.length === 0 && Array.isArray(deviceRecord?.snapshot?.recentInvoices)) {
    recentInvoices = deviceRecord.snapshot.recentInvoices;
  }
  if (!activeShift) {
    activeShift = deviceRecord?.snapshot?.current_shift || deviceRecord?.snapshot?.activeShift || null;
  }

  const avgTicketCents = totalInvoicesCount > 0 ? Math.round(totalSalesCents / totalInvoicesCount) : 0;
  const netProfitCents = pgNetProfitCents !== null ? pgNetProfitCents : Number(deviceRecord?.snapshot?.today?.net_profit_cents || 0);
  const profitMargin = pgProfitMarginPct !== null ? pgProfitMarginPct : (totalSalesCents > 0 ? Math.round((netProfitCents / totalSalesCents) * 1000) / 10 : 0);
  const lowStock = Array.isArray(deviceRecord?.snapshot?.lowStockProducts) ? deviceRecord.snapshot.lowStockProducts : [];

  const aggregatedSnapshot = {
    today: {
      total_sales: totalSalesCents / 100,
      total_sales_cents: totalSalesCents,
      invoices_count: totalInvoicesCount,
      average_ticket: avgTicketCents / 100,
      average_ticket_cents: avgTicketCents,
      net_profit: netProfitCents / 100,
      net_profit_cents: netProfitCents,
      profit_margin: profitMargin,
      payment_methods: {
        cash: cashCents / 100,
        card: cardCents / 100,
        instapay: instapayCents / 100,
        credit: creditCents / 100,
      },
      payment_methods_cents: {
        cashCents,
        cardCents,
        instapayCents,
        creditCents,
      }
    },
    current_shift: activeShift,
    activeShift: activeShift,
    alerts: {
      low_stock_count: lowStock.length,
      pending_invoices_count: 0,
      active_devices_count: activeDevices.length
    },
    salesSummary: {
      todayTotalCents: totalSalesCents,
      todayInvoiceCount: totalInvoicesCount,
      averageInvoiceCents: avgTicketCents,
      netProfitCents,
      profitMarginPct: profitMargin,
    },
    paymentBreakdown: {
      cashCents,
      cardCents,
      instapayCents,
      creditCents,
    },
    recentInvoices: recentInvoices.slice(0, 50),
    lowStockProducts: lowStock.slice(0, 50),
    last_sync: new Date().toLocaleTimeString('ar-EG', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
  };

  const finalStoreRecord = {
    token,
    deviceId: currentDevId,
    machineId: currentDevId,
    activeDevices,
    storeName: deviceRecord.storeName || 'أمان كاشير',
    sequenceNumber: deviceRecord.sequenceNumber,
    idempotencyKey: deviceRecord.idempotencyKey,
    snapshot: aggregatedSnapshot,
    lastSync: new Date().toISOString(),
    lastIp: deviceRecord.lastIp || '',
    storageTier: 'POSTGRESQL_DURABLE'
  };

  try {
    if (redis) {
      await redis.set(`snapshot:${token}`, finalStoreRecord);
      await redis.set(`devices:${token}`, activeDevices);
    }
  } catch (e) {
    console.warn('[Redis Aggregated Store Error]:', e.message);
  }
  cloudSnapshots.set(token, finalStoreRecord);

  return finalStoreRecord;
}

async function setPersistedSnapshot(token, record) {
  try {
    if (redis) {
      await redis.set(`snapshot:${token}`, record);
    }
  } catch (e) {
    console.warn('[Redis Write Error]:', e.message);
  }
  cloudSnapshots.set(token, record);
}

function canonicalJsonStringify(data) {
  if (data === null || data === undefined) return 'null';
  if (typeof data === 'boolean' || typeof data === 'number') return JSON.stringify(data);
  if (typeof data === 'string') return JSON.stringify(data);
  if (Array.isArray(data)) {
    return '[' + data.map(canonicalJsonStringify).join(',') + ']';
  }
  if (typeof data === 'object') {
    return '{' + Object.keys(data).sort().filter(k => data[k] !== undefined).map(k => JSON.stringify(k) + ':' + canonicalJsonStringify(data[k])).join(',') + '}';
  }
  return JSON.stringify(data);
}

function signPayload(payload) {
  const privateKey = getPrivateKey();
  const signer = crypto.createSign('sha256');
  const buf = Buffer.from(canonicalJsonStringify(payload), 'utf8');
  signer.update(buf);
  return signer.sign(privateKey, 'hex');
}

function logServerAudit(action, machineId, storeName, details, ip) {
  const entry = {
    id: 'AUD-' + Date.now().toString(36) + '-' + Math.random().toString(36).substring(2, 5),
    timestamp: new Date().toISOString(),
    action,
    machineId: machineId || 'UNKNOWN',
    storeName: storeName || 'UNKNOWN',
    details: details || '',
    ip: ip || 'unknown',
  };
  auditStore.unshift(entry);
  if (auditStore.length > 200) auditStore.pop();
}

function getOrCreateDeviceList(keyEntry) {
  if (!keyEntry.devices) keyEntry.devices = [];
  if (Array.isArray(keyEntry.activatedDevices)) {
    keyEntry.activatedDevices.forEach(mId => {
      if (typeof mId === 'string' && !keyEntry.devices.some(d => d.machineId === mId)) {
        keyEntry.devices.push({
          deviceId: 'DEV-' + Math.random().toString(36).substring(2, 8).toUpperCase(),
          machineId: mId,
          deviceName: 'جهاز كاشير',
          activatedAt: new Date().toISOString(),
          lastSeenAt: new Date().toISOString(),
          status: 'ACTIVE'
        });
      }
    });
  }
  return keyEntry.devices;
}

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

function getAdminApiKey() {
  return (process.env.ADMIN_API_KEY || '').trim();
}

function isAdminAuthorized(req, res) {
  const adminKey = getAdminApiKey();
  if (!adminKey) return true;
  const provided = String(req.headers['x-admin-key'] || '');
  const a = Buffer.from(provided);
  const b = Buffer.from(adminKey);
  if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  res.status(401).json({ success: false, error: 'Unauthorized: يلزم مفتاح إدارة السيرفر (ADMIN_API_KEY)' });
  return false;
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      if (!body || !body.trim()) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new Error('INVALID_JSON: Failed to parse request JSON body.'));
      }
    });
    req.on('error', err => reject(err));
  });
}

async function authenticateAdminOrPlatformRole(req, pool) {
  const adminKey = getAdminApiKey();

  // Method 1: X-Admin-Key Header
  if (adminKey) {
    const provided = String(req.headers['x-admin-key'] || '');
    if (provided) {
      const a = Buffer.from(provided);
      const b = Buffer.from(adminKey);
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
        return { authorized: true, authMethod: 'ADMIN_KEY', actor: { userId: 'sys_admin_key', role: 'PLATFORM_ADMIN', orgId: 'ORG-SYSTEM' } };
      }
    }
  }

  // Method 2: JWT Bearer Token with PLATFORM_ADMIN role or LICENSES_ISSUE permission
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    if (!pool) {
      return { authorized: false, statusCode: 503, error: 'DATABASE_UNAVAILABLE', message: 'Database client unavailable for JWT verification.' };
    }
    const authCheck = await auth.authenticateRequest(pool, authHeader);
    if (authCheck.authenticated) {
      const userRole = authCheck.user.role;
      if (userRole === 'PLATFORM_ADMIN' || rbac.hasPermission(userRole, rbac.PERMISSIONS.LICENSES_ISSUE)) {
        return { authorized: true, authMethod: 'JWT_BEARER', actor: authCheck.user };
      }
      return { authorized: false, statusCode: 403, error: 'FORBIDDEN', message: 'Platform admin role or licenses.issue permission required.' };
    }
    return { authorized: false, statusCode: authCheck.statusCode || 401, error: authCheck.error };
  }

  // Fallback in development ONLY if explicitly allowed and NODE_ENV != production
  const envStr = (process.env.NODE_ENV || process.env.VERCEL_ENV || '').toLowerCase();
  const isProd = envStr === 'production';
  if (!adminKey && !isProd && process.env.ALLOW_DEV_UNPROTECTED_ADMIN === 'true') {
    return { authorized: true, authMethod: 'DEV_UNPROTECTED_FALLBACK', actor: { userId: 'sys_dev_admin', role: 'PLATFORM_ADMIN', orgId: 'ORG-SYSTEM' } };
  }

  return { authorized: false, statusCode: 401, error: 'UNAUTHORIZED', message: 'Authentication required. Provide valid X-Admin-Key header or Bearer JWT token.' };
}



module.exports = async (req, res) => {
  if (!res.status) {
    res.status = function(code) {
      this.statusCode = code;
      return this;
    };
  }
  if (!res.json) {
    res.json = function(data) {
      this.setHeader('Content-Type', 'application/json');
      this.end(JSON.stringify(data));
      return this;
    };
  }

  const origin = req.headers.origin;
  const requestHost = (req.headers.host || '').toLowerCase();
  const isAllowed =
    !origin ||
    ((origin.replace(/^https?:\/\//, '') || '').split('/')[0].toLowerCase() === requestHost) ||
    ALLOWED_ORIGINS.includes(origin);
  if (isAllowed && origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, OPTIONS, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-admin-key');

  // Standard Production Security Headers (FINDING-PROD-03)
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:;");

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;
  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '';

  try {
    // 0. Static Web UI Files
    if ((pathname === '/' || pathname === '/index.html') && req.method === 'GET') {
      const htmlPath = path.join(__dirname, 'index.html');
      if (fs.existsSync(htmlPath)) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.end(fs.readFileSync(htmlPath, 'utf8'));
      }
    }

    if (pathname === '/mobile.html' && req.method === 'GET') {
      const mobilePath = path.join(__dirname, 'mobile.html');
      if (fs.existsSync(mobilePath)) {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.end(fs.readFileSync(mobilePath, 'utf8'));
      }
    }

    if ((pathname === '/aman_logo.jpg' || pathname === '/public/aman_logo.jpg') && req.method === 'GET') {
      const logoPath = path.join(__dirname, '../../src/assets/aman_logo.jpg');
      if (fs.existsSync(logoPath)) {
        res.setHeader('Content-Type', 'image/jpeg');
        return res.end(fs.readFileSync(logoPath));
      }
    }

    // 0.5 GET /api/health
    if (pathname === '/api/health' && req.method === 'GET') {
      const pgHealth = await db.checkPostgresHealth();
      let redisHealthy = false;
      try {
        if (redis) {
          await redis.ping();
          redisHealthy = true;
        }
      } catch (e) {
        redisHealthy = false;
      }
      return res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        postgres: pgHealth,
        redis: { available: redisHealthy }
      });
    }

    // 1. GET /api/history
    if (pathname === '/api/history' && req.method === 'GET') {
      const authRes = await authenticateAdminOrPlatformRole(req, db.getPool());
      if (!authRes.authorized) {
        return res.status(authRes.statusCode || 401).json({
          success: false,
          error: authRes.error,
          message: authRes.message || 'Authentication required for history'
        });
      }
      return res.status(200).json(memoryStore);
    }

    // 2. GET /api/stats
    if (pathname === '/api/stats' && req.method === 'GET') {
      const total = memoryStore.length;
      let active = 0;
      let expired = 0;
      let revoked = 0;
      let trial = 0;
      const now = Date.now();

      memoryStore.forEach(item => {
        if (item.status === 'REVOKED') {
          revoked++;
        } else if (item.expiryDate === 'PERMANENT') {
          active++;
        } else {
          const exp = new Date(item.expiryDate).getTime();
          if (exp < now) {
            expired++;
          } else {
            active++;
            trial++;
          }
        }
      });

      return res.status(200).json({ total, active, expired, revoked, trial });
    }

    // 3. GET /api/audit-logs
    if (pathname === '/api/audit-logs' && req.method === 'GET') {
      const authRes = await authenticateAdminOrPlatformRole(req, db.getPool());
      if (!authRes.authorized) {
        return res.status(authRes.statusCode || 401).json({
          success: false,
          error: authRes.error,
          message: authRes.message || 'Authentication required for audit logs'
        });
      }
      return res.status(200).json(auditStore);
    }

    // 4. GET /api/check-license?machineId=XXX
    if (pathname === '/api/check-license' && req.method === 'GET') {
      const machineId = (url.searchParams.get('machineId') || '').trim().toUpperCase();
      if (!machineId) {
        return res.status(400).json({ found: false, error: 'machineId required' });
      }

      // البحث في سجل التراخيص وسجل المفاتيح
      const entry = memoryStore.find(e => e.machineId && e.machineId.toUpperCase() === machineId);
      
      // البحث أيضاً في productKeysStore
      let matchingKeyEntry = null;
      let matchingDevice = null;
      for (const pk of productKeysStore) {
        const devList = getOrCreateDeviceList(pk);
        const d = devList.find(dev => dev.machineId && dev.machineId.toUpperCase() === machineId);
        if (d) {
          matchingKeyEntry = pk;
          matchingDevice = d;
          break;
        }
      }

      // التحقق من حالة الإلغاء (Revocation Check)
      if (
        (entry && entry.status === 'REVOKED') ||
        (matchingKeyEntry && matchingKeyEntry.status === 'REVOKED') ||
        (matchingDevice && matchingDevice.status === 'REVOKED')
      ) {
        return res.status(200).json({
          found: true,
          revoked: true,
          status: 'REVOKED',
          message: 'تم إلغاء ترخيص هذا الجهاز من قبل الإدارة المركزية.'
        });
      }

      // التحقق من حالة فك الربط (Deactivated Check)
      if (
        (entry && entry.status === 'DEACTIVATED') ||
        (matchingDevice && matchingDevice.status === 'DEACTIVATED')
      ) {
        return res.status(200).json({
          found: true,
          deactivated: true,
          status: 'DEACTIVATED',
          message: 'تم فك ربط هذا الجهاز من كود التفعيل.'
        });
      }

      if (!entry) {
        return res.status(404).json({ found: false, error: 'الترخيص غير موجود أو تم حذفه من السيرفر' });
      }

      entry.lastCheckAt = new Date().toISOString();
      entry.lastIp = ip;
      if (matchingDevice) matchingDevice.lastSeenAt = new Date().toISOString();

      return res.status(200).json({
        found: true,
        licenseData: entry.licenseData,
        storeName: entry.storeName,
        expiryDate: entry.expiryDate,
        status: entry.status || 'ACTIVE'
      });
    }

    // 4b. POST /api/activate (Product Key Activation & Multi-Device Control)
    if (pathname === '/api/activate' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const { productKey, machineId, storeName, deviceName } = JSON.parse(body);
          if (!productKey || !machineId) {
            return res.status(400).json({ success: false, error: 'كود التفعيل وبصمة الجهاز مطلوبان.' });
          }

          const cleanKey = productKey.trim().toUpperCase();
          const cleanMachineId = machineId.trim().toUpperCase();

          // 1. البحث في قاعدة أكواد التفعيل
          let keyEntry = productKeysStore.find(k => k.productKey === cleanKey);
          if (!keyEntry) {
            keyEntry = memoryStore.find(m => m.productKey === cleanKey || m.id === cleanKey);
          }

          // إذا لم يوجد كود مسجل مسبقاً، نتحقق من صيغة AMAN-XXXX-XXXX-XXXX
          if (!keyEntry) {
            const keyRegex = /^AMAN-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;
            if (keyRegex.test(cleanKey)) {
              keyEntry = {
                productKey: cleanKey,
                storeName: storeName?.trim() || 'متجر معتمد',
                expiryDate: 'PERMANENT',
                licenseType: 'PERPETUAL',
                plan: 'PRO',
                features: ['FULL_POS', 'INVENTORY', 'REPORTS', 'BACKUP'],
                maxDevices: 1,
                devices: [],
                status: 'ACTIVE',
                createdAt: new Date().toISOString()
              };
              productKeysStore.push(keyEntry);
            }
          }

          if (!keyEntry) {
            return res.status(404).json({ success: false, error: 'كود التفعيل غير صالح أو غير موجود على السيرفر.' });
          }

          // فحص حالة كود التفعيل
          if (keyEntry.status === 'REVOKED') {
            return res.status(403).json({ success: false, error: 'تم إلغاء كود التفعيل هذا من قبل الإدارة.' });
          }
          if (keyEntry.status === 'SUSPENDED') {
            return res.status(403).json({ success: false, error: 'كود التفعيل معلق مؤقتاً. يرجى مراجعة الدعم.' });
          }

          const devList = getOrCreateDeviceList(keyEntry);
          const maxDevices = keyEntry.maxDevices || 1;
          const activeDevices = devList.filter(d => d.status === 'ACTIVE');
          let existingDevice = devList.find(d => d.machineId === cleanMachineId);

          if (existingDevice) {
            if (existingDevice.status === 'REVOKED') {
              return res.status(403).json({
                success: false,
                error: 'تم إلغاء ترخيص هذا الجهاز بشكل دائم من قبل الإدارة.'
              });
            }
            if (existingDevice.status === 'DEACTIVATED') {
              if (activeDevices.length >= maxDevices) {
                return res.status(403).json({
                  success: false,
                  error: `تم استنفاد الحد الأقصى للأجهزة المسموح بها لهذا الكود (${maxDevices} جهاز).`
                });
              }
              existingDevice.status = 'ACTIVE';
              existingDevice.lastSeenAt = new Date().toISOString();
              existingDevice.deactivatedAt = null;
            } else {
              // جهاز نشط بالفعل: إعادة توليد متطابقة (Idempotent Re-activation)
              existingDevice.lastSeenAt = new Date().toISOString();
            }
          } else {
            // جهاز جديد يحاول التفعيل
            if (activeDevices.length >= maxDevices) {
              return res.status(403).json({
                success: false,
                error: `تم استنفاد الحد الأقصى للأجهزة المسموح بها لهذا الكود (${maxDevices} جهاز).`
              });
            }
            existingDevice = {
              deviceId: 'DEV-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substring(2, 5).toUpperCase(),
              machineId: cleanMachineId,
              deviceName: deviceName?.trim() || 'جهاز كاشير',
              activatedAt: new Date().toISOString(),
              lastSeenAt: new Date().toISOString(),
              status: 'ACTIVE'
            };
            devList.push(existingDevice);
          }

          // مزامنة activatedDevices للتوافق القديم
          keyEntry.activatedDevices = devList.filter(d => d.status === 'ACTIVE').map(d => d.machineId);

          const targetStoreName = storeName?.trim() || keyEntry.storeName || 'متجر معتمد';
          const targetExpiry = keyEntry.expiryDate || 'PERMANENT';

          const payload = {
            licenseId: 'LIC-' + Date.now().toString(36).toUpperCase(),
            productKey: cleanKey,
            machineId: cleanMachineId,
            storeName: targetStoreName,
            plan: keyEntry.plan || 'PRO',
            licenseType: keyEntry.licenseType || 'PERPETUAL',
            features: keyEntry.features || ['FULL_POS', 'INVENTORY', 'REPORTS', 'BACKUP'],
            maxDevices: maxDevices,
            issuedAt: new Date().toISOString(),
            expiryDate: targetExpiry,
            version: 1
          };

          const signature = signPayload(payload);
          const licenseObject = { data: payload, signature };

          // حفظ/تحديث سجل الجهاز في memoryStore
          const existingIdx = memoryStore.findIndex(e => e.machineId === cleanMachineId);
          const licenseRecord = {
            id: payload.licenseId,
            productKey: cleanKey,
            machineId: cleanMachineId,
            storeName: targetStoreName,
            expiryDate: targetExpiry,
            licenseType: payload.licenseType,
            issuedAt: payload.issuedAt,
            status: 'ACTIVE',
            licenseData: licenseObject,
          };

          if (existingIdx >= 0) {
            memoryStore[existingIdx] = licenseRecord;
          } else {
            memoryStore.unshift(licenseRecord);
          }

          logServerAudit('ACTIVATE_PRODUCT_KEY', cleanMachineId, targetStoreName, `تفعيل ناجح عبر كود التفعيل: ${cleanKey} (المقاعد المستخدمة: ${keyEntry.devices.filter(d=>d.status==='ACTIVE').length}/${maxDevices})`, ip);

          return res.status(200).json({
            success: true,
            found: true,
            licenseData: licenseObject,
            storeName: targetStoreName,
            expiryDate: targetExpiry,
            status: 'ACTIVE'
          });
        } catch (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
      });
      return;
    }

    // 5. POST /api/issue
    if (pathname === '/api/issue' && req.method === 'POST') {
      if (!isAdminAuthorized(req, res)) return;
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const { machineId, storeName, expiryDate, phone, notes, licenseType } = JSON.parse(body);
          if (!machineId || !storeName) {
            return res.status(400).json({ success: false, error: 'machineId and storeName are required' });
          }

          const cleanMachineId = machineId.trim().toUpperCase();
          const cleanStoreName = storeName.trim();
          const cleanExpiry = expiryDate || 'PERMANENT';

          const payload = {
            machineId: cleanMachineId,
            storeName: cleanStoreName,
            expiryDate: cleanExpiry,
            licenseType: licenseType || 'CUSTOM',
            issuedAt: new Date().toISOString(),
          };

          const signature = signPayload(payload);
          const licenseObject = { data: payload, signature };

          const existingIdx = memoryStore.findIndex(e => e.machineId === cleanMachineId);
          const entry = {
            id: 'LIC-' + Date.now().toString(36).toUpperCase(),
            machineId: cleanMachineId,
            storeName: cleanStoreName,
            expiryDate: cleanExpiry,
            licenseType: payload.licenseType,
            issuedAt: payload.issuedAt,
            phone: (phone || '').trim(),
            notes: (notes || '').trim(),
            status: 'ACTIVE',
            licenseData: licenseObject,
          };

          if (existingIdx >= 0) {
            memoryStore[existingIdx] = entry;
          } else {
            memoryStore.unshift(entry);
          }

          logServerAudit('ISSUE_LICENSE', cleanMachineId, cleanStoreName, `توليد ترخيص جديد (${cleanExpiry})`, ip);

          return res.status(200).json({
            success: true,
            entry,
            licenseJson: JSON.stringify(licenseObject, null, 2)
          });
        } catch (e) {
          return res.status(500).json({ success: false, error: e.message });
        }
      });
      return;
    }

    // 6. POST /api/extend
    if (pathname === '/api/extend' && req.method === 'POST') {
      if (!isAdminAuthorized(req, res)) return;
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const { id, addHours, addDays } = JSON.parse(body);
          const entry = memoryStore.find(e => e.id === id);
          if (!entry) return res.status(404).json({ success: false, error: 'License not found' });

          let baseDate = new Date();
          if (entry.expiryDate !== 'PERMANENT') {
            const curExp = new Date(entry.expiryDate);
            if (curExp.getTime() > Date.now()) {
              baseDate = curExp;
            }
          }

          if (addHours) baseDate.setHours(baseDate.getHours() + Number(addHours));
          if (addDays) baseDate.setDate(baseDate.getDate() + Number(addDays));

          entry.expiryDate = baseDate.toISOString();
          entry.status = 'ACTIVE';
          entry.licenseData.data.expiryDate = entry.expiryDate;
          entry.licenseData.signature = signPayload(entry.licenseData.data);

          logServerAudit('EXTEND_LICENSE', entry.machineId, entry.storeName, `تمديد الصلاحية حتى ${entry.expiryDate}`, ip);

          return res.status(200).json({ success: true, entry });
        } catch (e) {
          return res.status(500).json({ success: false, error: e.message });
        }
      });
      return;
    }

    // 7. POST /api/revoke (Revoke License, Device, or Product Key)
    if (pathname === '/api/revoke' && req.method === 'POST') {
      if (!isAdminAuthorized(req, res)) return;
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const { id, machineId, productKey, reason } = JSON.parse(body || '{}');
          const cleanKey = productKey ? productKey.trim().toUpperCase() : '';
          const cleanMachineId = machineId ? machineId.trim().toUpperCase() : '';
          const revocationReason = reason?.trim() || 'إلغاء الترخيص من قبل الإدارة المركزية';

          let revokedCount = 0;

          // 1. إلغاء كود تفعيل بالكامل
          if (cleanKey) {
            const keyEntry = productKeysStore.find(k => k.productKey === cleanKey);
            if (keyEntry) {
              keyEntry.status = 'REVOKED';
              keyEntry.revokedAt = new Date().toISOString();
              keyEntry.revocationReason = revocationReason;
              const devList = getOrCreateDeviceList(keyEntry);
              devList.forEach(d => { d.status = 'REVOKED'; });
              revokedCount++;
            }
            memoryStore.filter(m => m.productKey === cleanKey).forEach(m => {
              m.status = 'REVOKED';
              revokedCount++;
            });
            logServerAudit('REVOKE_PRODUCT_KEY', cleanKey, '', `إلغاء كود التفعيل: ${cleanKey} (${revocationReason})`, ip);
          }

          // 2. إلغاء جهاز محدد
          if (cleanMachineId) {
            productKeysStore.forEach(pk => {
              const devList = getOrCreateDeviceList(pk);
              const d = devList.find(dev => dev.machineId === cleanMachineId);
              if (d) {
                d.status = 'REVOKED';
                revokedCount++;
              }
            });
            memoryStore.filter(m => m.machineId === cleanMachineId).forEach(m => {
              m.status = 'REVOKED';
              revokedCount++;
            });
            logServerAudit('REVOKE_DEVICE', cleanMachineId, '', `إلغاء جهاز كاشير: ${cleanMachineId} (${revocationReason})`, ip);
          }

          // 3. إلغاء عبر معرف الترخيص (License ID)
          if (id) {
            const entry = memoryStore.find(e => e.id === id);
            if (entry) {
              entry.status = 'REVOKED';
              if (entry.machineId) {
                productKeysStore.forEach(pk => {
                  const devList = getOrCreateDeviceList(pk);
                  const d = devList.find(dev => dev.machineId === entry.machineId);
                  if (d) d.status = 'REVOKED';
                });
              }
              revokedCount++;
              logServerAudit('REVOKE_LICENSE', entry.machineId, entry.storeName, `إلغاء الترخيص: ${id} (${revocationReason})`, ip);
            }
          }

          if (revokedCount === 0) {
            return res.status(404).json({ success: false, error: 'لم يتم العثور على الترخيص أو الجهاز المطلوب إلغاؤه.' });
          }

          return res.status(200).json({
            success: true,
            message: 'تم إلغاء الترخيص بنجاح.',
            revokedCount
          });
        } catch (e) {
          return res.status(500).json({ success: false, error: e.message });
        }
      });
      return;
    }

    // 7b. POST /api/deactivate-device (Admin Device Management / Release Slot)
    if (pathname === '/api/deactivate-device' && req.method === 'POST') {
      if (!isAdminAuthorized(req, res)) return;
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const { productKey, machineId, reason } = JSON.parse(body || '{}');
          if (!machineId) {
            return res.status(400).json({ success: false, error: 'machineId مطلوب لفك ربط الجهاز.' });
          }

          const cleanMachineId = machineId.trim().toUpperCase();
          const cleanKey = productKey ? productKey.trim().toUpperCase() : '';
          const deactReason = reason?.trim() || 'فك ربط الجهاز لإتاحة مقعد جديد';

          let deactivated = false;
          let targetKey = null;

          // البحث في productKeysStore
          for (const pk of productKeysStore) {
            if (cleanKey && pk.productKey !== cleanKey) continue;
            const devList = getOrCreateDeviceList(pk);
            const dev = devList.find(d => d.machineId === cleanMachineId);
            if (dev) {
              dev.status = 'DEACTIVATED';
              dev.deactivatedAt = new Date().toISOString();
              dev.deactivationReason = deactReason;
              pk.activatedDevices = devList.filter(d => d.status === 'ACTIVE').map(d => d.machineId);
              targetKey = pk;
              deactivated = true;
              break;
            }
          }

          // تحديث في memoryStore
          const memEntry = memoryStore.find(m => m.machineId === cleanMachineId);
          if (memEntry) {
            memEntry.status = 'DEACTIVATED';
            deactivated = true;
          }

          if (!deactivated) {
            return res.status(404).json({ success: false, error: 'لم يتم العثور على الجهاز المراد فك ربطه.' });
          }

          const activeCount = targetKey ? targetKey.devices.filter(d => d.status === 'ACTIVE').length : 0;
          const maxDevs = targetKey ? (targetKey.maxDevices || 1) : 1;

          logServerAudit('DEACTIVATE_DEVICE', cleanMachineId, targetKey?.storeName || '', `فك ربط جهاز: ${cleanMachineId} (${deactReason}) — المقاعد المتاحة: ${maxDevs - activeCount}/${maxDevs}`, ip);

          return res.status(200).json({
            success: true,
            message: 'تم فك ربط الجهاز بنجاح وإتاحة المقعد لتفعيل جهاز بديل.',
            activeDevicesCount: activeCount,
            availableSlots: maxDevs - activeCount,
            maxDevices: maxDevs
          });
        } catch (e) {
          return res.status(500).json({ success: false, error: e.message });
        }
      });
      return;
    }

    // 7c. GET /api/devices (List connected devices for Product Key)
    if (pathname === '/api/devices' && req.method === 'GET') {
      if (!isAdminAuthorized(req, res)) return;
      const productKey = (url.searchParams.get('productKey') || '').trim().toUpperCase();
      if (!productKey) {
        return res.status(400).json({ success: false, error: 'productKey parameter required' });
      }

      const keyEntry = productKeysStore.find(k => k.productKey === productKey);
      if (!keyEntry) {
        return res.status(404).json({ success: false, error: 'كود التفعيل غير موجود' });
      }

      const devList = getOrCreateDeviceList(keyEntry);
      return res.status(200).json({
        success: true,
        productKey: keyEntry.productKey,
        storeName: keyEntry.storeName,
        maxDevices: keyEntry.maxDevices || 1,
        status: keyEntry.status,
        activeCount: devList.filter(d => d.status === 'ACTIVE').length,
        devices: devList
      });
    }

    // 8. POST /api/reactivate
    if (pathname === '/api/reactivate' && req.method === 'POST') {
      if (!isAdminAuthorized(req, res)) return;
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const { id } = JSON.parse(body);
          const entry = memoryStore.find(e => e.id === id);
          if (!entry) return res.status(404).json({ success: false, error: 'License not found' });

          entry.status = 'ACTIVE';
          if (entry.machineId) {
            productKeysStore.forEach(pk => {
              const devList = getOrCreateDeviceList(pk);
              const d = devList.find(dev => dev.machineId === entry.machineId);
              if (d) d.status = 'ACTIVE';
            });
          }

          logServerAudit('REACTIVATE_LICENSE', entry.machineId, entry.storeName, 'إعادة تفعيل الترخيص', ip);

          return res.status(200).json({ success: true, entry });
        } catch (e) {
          return res.status(500).json({ success: false, error: e.message });
        }
      });
      return;
    }

    // 9. DELETE /api/delete/:id
    if (pathname.startsWith('/api/delete/')) {
      if (!isAdminAuthorized(req, res)) return;
      const id = pathname.replace('/api/delete/', '');
      const idx = memoryStore.findIndex(e => e.id === id);
      if (idx >= 0) {
        const removed = memoryStore.splice(idx, 1)[0];
        logServerAudit('DELETE_LICENSE', removed.machineId, removed.storeName, 'حذف الترخيص نهائياً', ip);
        return res.status(200).json({ success: true });
      }
      return res.status(404).json({ success: false, error: 'Not found' });
    }

    // ═════════════════════════════════════════════════════════════════════════
    // ☁️ CLOUD LIVE MONITORING (Read-Only Mobile Portal APIs)
    // ═════════════════════════════════════════════════════════════════════════

    // 10. POST /api/sync, /api/cloud/sync, /api/data & /api/v1/sync/events (Durable Relational Event Ingestion & Cache Projection)
    if ((pathname === '/api/sync' || pathname === '/api/cloud/sync' || pathname === '/api/data' || pathname === '/api/v1/sync/push' || pathname === '/api/v1/sync/events') && req.method === 'POST') {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');

      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const parsed = JSON.parse(body || '{}');
          const token = (parsed.token || parsed.storeId || '').trim();
          const deviceId = (parsed.deviceId || parsed.machineId || 'POS-01').trim();
          const deviceKey = (parsed.deviceKey || req.headers['x-device-key'] || '').trim();
          const machineId = (parsed.machineId || req.headers['x-device-fingerprint'] || '').trim();
          const storeName = (parsed.storeName || 'أمان كاشير').trim();
          const idempotencyKey = parsed.idempotencyKey || req.headers['idempotency-key'] || '';
          const sequenceNumber = Number(parsed.sequenceNumber) || 100;
          const incomingEvents = Array.isArray(parsed.events) ? parsed.events : [];
          const snapshot = parsed.snapshot || parsed.dashboard || (parsed.events ? null : parsed);

          const isProduction = process.env.NODE_ENV === 'production' || process.env.APP_ENV === 'production' || process.env.VERCEL_ENV === 'production';
          const hasPg = Boolean(db.DATABASE_URL || db.getPool());

          // ═══════════════════════════════════════════════════════════════════
          // PRODUCTION GUARD: FAIL-CLOSED IF DATABASE_URL IS MISSING
          // ═══════════════════════════════════════════════════════════════════
          if (isProduction && !hasPg) {
            console.error('[CRITICAL PRODUCTION CONFIG ERROR]: DATABASE_URL is missing in production environment. Refusing sync request.');
            return res.status(503).json({
              success: false,
              error: 'CRITICAL_CONFIGURATION_ERROR: DATABASE_URL is strictly required in production. In-memory / Redis fallback is prohibited in production.',
              code: 'PG_REQUIRED_IN_PRODUCTION'
            });
          }

          // ═══════════════════════════════════════════════════════════════════
          // TIER 1: DURABLE POSTGRESQL ACID COMMIT (When Database is Configured)
          // ═══════════════════════════════════════════════════════════════════
          if (hasPg) {
            await db.initSchema();

            let dbResult;
            try {
              dbResult = await db.withTransaction(async (client) => {
                // 1. Authoritative Server-Side Tenant & Pairing Resolution
                const auth = await resolveCloudTenantAuth(client, { token, deviceId, deviceKey, machineId });
                if (!auth.authorized) {
                  const authErr = new Error(auth.error);
                  authErr.statusCode = auth.status;
                  authErr.code = auth.code;
                  throw authErr;
                }

                const effectiveOrgId = auth.orgId;
                const effectiveStoreId = auth.storeId;
                const effectiveDeviceId = auth.deviceId;

                // 2. Server-side Universal Idempotency Check on Ledger
                if (idempotencyKey) {
                  const ledgerCheck = await client.query(`
                    SELECT response_payload FROM executed_operations_ledger
                    WHERE org_id = $1 AND idempotency_key = $2
                    LIMIT 1
                  `, [effectiveOrgId, idempotencyKey]);

                  if (ledgerCheck.rows && ledgerCheck.rows.length > 0) {
                    const cachedPayload = ledgerCheck.rows[0].response_payload || {};
                    return {
                      processedEventIds: incomingEvents.map(e => e.eventId || e.id).filter(Boolean),
                      committedCount: 0,
                      duplicateCount: incomingEvents.length,
                      isIdempotentReplay: true,
                      cachedResponse: cachedPayload
                    };
                  }
                }

                const committedEventIds = [];
                const duplicateEventIds = [];

                for (const ev of incomingEvents) {
                  const evId = ev.eventId || ev.id;
                  if (!evId) continue;

                  const evType = ev.type || ev.event_type || 'INVOICE_CREATED';
                  const entityType = ev.entityType || ev.entity_type || 'INVOICE';
                  const entityId = ev.entityId || ev.entity_id || evId;
                  const evSeq = Number(ev.sequence || ev.sequence_number) || 0;
                  let evPayload = {};
                  const rawPayload = ev.payload;
                  if (typeof rawPayload === 'string') {
                    try {
                      evPayload = JSON.parse(rawPayload);
                    } catch (pErr) {
                      evPayload = {};
                    }
                  } else if (rawPayload && typeof rawPayload === 'object') {
                    evPayload = rawPayload;
                  }
                  const evCreatedAt = ev.createdAt || ev.created_at || new Date().toISOString();

                  // 1. Immutable Event Store Insert with UNIQUE constraint
                  const insertEvRes = await client.query(`
                    INSERT INTO cloud_events (
                      org_id, store_id, store_token, device_id, event_id, event_type, entity_type, entity_id, sequence_number, payload, received_at, processed_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
                    ON CONFLICT (store_token, device_id, event_id) DO NOTHING
                    RETURNING id
                  `, [effectiveOrgId, effectiveStoreId, token, effectiveDeviceId, evId, evType, entityType, entityId, evSeq, JSON.stringify(evPayload)]);

                  const isNewEvent = insertEvRes.rowCount > 0;

                  if (isNewEvent) {
                    committedEventIds.push(evId);

                    // 2. Relational Entity Projections
                    const isReturnEvent = evType === 'CUSTOMER_RETURN' || evType === 'RETURN_PROCESSED' || entityType === 'RETURN';
                    const isInvoiceEvent = (evType === 'INVOICE_CREATED' || evType === 'SALE_COMPLETED' || entityType === 'INVOICE') && !isReturnEvent;

                    if (isInvoiceEvent) {
                      const inv = evPayload.invoice || evPayload;
                      const invoiceLocalId = String(inv.id || inv.invoiceId || (entityType === 'INVOICE' ? entityId : null) || evId);
                      const invoiceNum = String(inv.invoice_number || inv.invoiceNumber || inv.invoice_num || evId);
                      const pMethodRaw = String(inv.payment_method || inv.paymentMethod || 'CASH').trim().toUpperCase();
                      const pMethod = pMethodRaw === 'CASH' ? 'CASH' : (pMethodRaw === 'CARD' ? 'CARD' : (['INSTAPAY', 'VODAFONE_CASH', 'WALLET'].includes(pMethodRaw) ? 'INSTAPAY' : (pMethodRaw === 'CREDIT' ? 'CREDIT' : pMethodRaw)));
                      const subtotalCents = Number(inv.subtotal_cents !== undefined ? inv.subtotal_cents : (inv.total_amount !== undefined ? inv.total_amount : (inv.subtotal !== undefined ? inv.subtotal : 0))) || 0;
                      const discountCents = Number(inv.discount_cents !== undefined ? inv.discount_cents : (inv.discount_amount !== undefined ? inv.discount_amount : (inv.discount !== undefined ? inv.discount : 0))) || 0;
                      const finalCents = Number(inv.final_amount_cents !== undefined ? inv.final_amount_cents : (inv.final_amount !== undefined ? inv.final_amount : (inv.finalTotal !== undefined ? inv.finalTotal : (subtotalCents - discountCents)))) || 0;
                      const paidCents = Number(inv.paid_amount_cents !== undefined ? inv.paid_amount_cents : (inv.paid_amount !== undefined ? inv.paid_amount : (inv.paidAmount !== undefined ? inv.paidAmount : finalCents))) || 0;
                      const changeCents = Number(inv.change_amount_cents !== undefined ? inv.change_amount_cents : (inv.change_amount !== undefined ? inv.change_amount : (inv.changeAmount || 0))) || 0;

                      await client.query(`
                        INSERT INTO cloud_invoices (
                          org_id, store_id, store_token, device_id, invoice_id_local, invoice_number, shift_id_local, cashier_name, customer_id, customer_name,
                          subtotal_cents, discount_cents, final_amount_cents, paid_amount_cents, change_amount_cents, payment_method, status, created_at, synced_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, NOW())
                        ON CONFLICT (store_token, invoice_id_local) DO UPDATE SET
                          status = EXCLUDED.status,
                          synced_at = NOW()
                      `, [
                        effectiveOrgId,
                        effectiveStoreId,
                        token,
                        effectiveDeviceId,
                        invoiceLocalId,
                        invoiceNum,
                        inv.shift_id || inv.shiftId ? String(inv.shift_id || inv.shiftId) : null,
                        inv.cashier_name || inv.cashierName || 'كاشير',
                        inv.customer_id || inv.customerId ? String(inv.customer_id || inv.customerId) : null,
                        inv.customer_name || inv.customerName || 'عميل نقدي',
                        subtotalCents,
                        discountCents,
                        finalCents,
                        paidCents,
                        changeCents,
                        pMethod,
                        inv.status || 'COMPLETED',
                        inv.created_at || inv.createdAt || evCreatedAt
                      ]);

                      // Line items & inventory movements
                      const items = Array.isArray(inv.items) ? inv.items : (Array.isArray(evPayload.items) ? evPayload.items : []);
                      for (const item of items) {
                        const pId = String(item.product_id || item.productId || item.id || 'ITEM-01');
                        const pName = item.product_name || item.productName || item.name || 'صنف';
                        const barcode = item.barcode || '';
                        let unitCost = 0;
                        if (item.unit_cost_cents !== undefined && item.unit_cost_cents !== null) {
                          unitCost = Math.round(Number(item.unit_cost_cents) || 0);
                        } else if (item.cost_price_cents !== undefined && item.cost_price_cents !== null) {
                          unitCost = Math.round(Number(item.cost_price_cents) || 0);
                        } else {
                          const rawCost = item.unit_cost_price ?? item.cost_price ?? item.costPrice ?? item.unit_cost ?? item.cost ?? item.buy_price ?? item.buyPrice ?? item.unitCost;
                          if (rawCost !== undefined && rawCost !== null) {
                            unitCost = Math.round((Number(rawCost) || 0) * 100);
                          }
                        }

                        let unitPrice = 0;
                        if (item.unit_price_cents !== undefined && item.unit_price_cents !== null) {
                          unitPrice = Math.round(Number(item.unit_price_cents) || 0);
                        } else if (item.selling_price_cents !== undefined && item.selling_price_cents !== null) {
                          unitPrice = Math.round(Number(item.selling_price_cents) || 0);
                        } else {
                          const rawPrice = item.unit_selling_price ?? item.selling_price ?? item.unitPrice ?? item.price;
                          if (rawPrice !== undefined && rawPrice !== null) {
                            unitPrice = Math.round((Number(rawPrice) || 0) * 100);
                          }
                        }

                        const qty = Number(item.quantity || 1);
                        let lineSubtotal = 0;
                        if (item.subtotal_cents !== undefined && item.subtotal_cents !== null) {
                          lineSubtotal = Math.round(Number(item.subtotal_cents) || 0);
                        } else if (item.subtotal !== undefined && item.subtotal !== null) {
                          lineSubtotal = Math.round((Number(item.subtotal) || 0) * 100);
                        } else if (item.itemSubtotal !== undefined && item.itemSubtotal !== null) {
                          lineSubtotal = Math.round((Number(item.itemSubtotal) || 0) * 100);
                        } else {
                          lineSubtotal = unitPrice * qty;
                        }

                        await client.query(`
                          INSERT INTO cloud_invoice_items (
                            org_id, store_id, store_token, device_id, invoice_id_local, product_id, product_name, barcode, unit_cost_cents, unit_price_cents, quantity, subtotal_cents, created_at
                          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                          ON CONFLICT (store_token, invoice_id_local, product_id) DO NOTHING
                        `, [
                          effectiveOrgId,
                          effectiveStoreId,
                          token,
                          effectiveDeviceId,
                          invoiceLocalId,
                          pId,
                          pName,
                          barcode,
                          unitCost,
                          unitPrice,
                          qty,
                          lineSubtotal,
                          inv.created_at || inv.createdAt || evCreatedAt
                        ]);

                        await client.query(`
                          INSERT INTO cloud_inventory_movements (
                            org_id, store_id, store_token, device_id, movement_id_local, product_id, movement_type, change_quantity, reference_id, created_at
                          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                          ON CONFLICT (store_token, movement_id_local) DO NOTHING
                        `, [
                          effectiveOrgId,
                          effectiveStoreId,
                          token,
                          effectiveDeviceId,
                          `MOV_${evId}_${pId}`,
                          pId,
                          'SALE',
                          -Math.abs(qty),
                          invoiceNum,
                          inv.created_at || inv.createdAt || evCreatedAt
                        ]);

                        // Update cloud_products stock
                        await client.query(`
                          UPDATE cloud_products
                          SET stock_quantity = stock_quantity - $1, updated_at = NOW()
                          WHERE store_token = $2 AND org_id = $3 AND store_id = $4 AND product_id_local = $5
                        `, [Math.abs(qty), token, effectiveOrgId, effectiveStoreId, pId]);
                      }
                    } else if (isReturnEvent) {
                      const ret = evPayload.return || evPayload;
                      const origInvoiceId = String(ret.originalInvoiceId || ret.original_invoice_id || ret.invoiceId || ret.invoice_id || '');
                      const returnNumber = String(ret.returnNumber || ret.return_number || ret.invoiceNumber || ret.invoice_number || evId);
                      const refundCents = Number(ret.refundTotalCents ?? ret.refund_amount_cents ?? ret.refundAmountCents ?? (ret.refundAmount ? ret.refundAmount * 100 : (ret.final_amount_cents ?? 0))) || 0;
                      const returnItems = Array.isArray(ret.items) ? ret.items : (Array.isArray(evPayload.items) ? evPayload.items : []);
                      const cashierName = ret.cashier_name || ret.cashierName || 'كاشير';
                      const shiftId = ret.shift_id || ret.shiftId ? String(ret.shift_id || ret.shiftId) : null;

                      // If original invoice exists, update its status
                      if (origInvoiceId) {
                        await client.query(`
                          UPDATE cloud_invoices
                          SET status = 'RETURNED', synced_at = NOW()
                          WHERE store_token = $1 AND org_id = $2 AND store_id = $3 AND (invoice_id_local = $4 OR invoice_number = $4)
                        `, [token, effectiveOrgId, effectiveStoreId, origInvoiceId]);
                      }

                      // Restock returned items
                      for (const item of returnItems) {
                        const pId = String(item.product_id || item.productId || item.id || 'ITEM-01');
                        const qty = Number(item.quantity || item.qty || 1);

                        await client.query(`
                          INSERT INTO cloud_inventory_movements (
                            org_id, store_id, store_token, device_id, movement_id_local, product_id, movement_type, change_quantity, reference_id, created_at
                          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                          ON CONFLICT (store_token, movement_id_local) DO NOTHING
                        `, [
                          effectiveOrgId,
                          effectiveStoreId,
                          token,
                          effectiveDeviceId,
                          `MOV_RET_${evId}_${pId}`,
                          pId,
                          'CUSTOMER_RETURN',
                          Math.abs(qty),
                          returnNumber || origInvoiceId,
                          ret.created_at || ret.createdAt || evCreatedAt
                        ]);

                        // Restock in cloud_products
                        await client.query(`
                          UPDATE cloud_products
                          SET stock_quantity = stock_quantity + $1, updated_at = NOW()
                          WHERE store_token = $2 AND org_id = $3 AND store_id = $4 AND product_id_local = $5
                        `, [Math.abs(qty), token, effectiveOrgId, effectiveStoreId, pId]);
                      }

                      // Record cash movement for return refund
                      if (refundCents > 0) {
                        await client.query(`
                          INSERT INTO cloud_cash_movements (
                            org_id, store_id, store_token, device_id, movement_id_local, shift_id_local, movement_type, amount_cents, reason, created_by, created_at
                          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                          ON CONFLICT (store_token, device_id, movement_id_local) DO NOTHING
                        `, [
                          effectiveOrgId,
                          effectiveStoreId,
                          token,
                          effectiveDeviceId,
                          `CASH_RET_${evId}`,
                          shiftId,
                          'RETURN',
                          refundCents,
                          `مرتجع مبيعات ${returnNumber}`,
                          cashierName,
                          ret.created_at || ret.createdAt || evCreatedAt
                        ]);
                      }
                    } else if (evType === 'PRODUCT_CREATED' || (entityType === 'PRODUCT' && evType !== 'INVENTORY_ADJUSTED')) {
                      const prod = evPayload.product || evPayload;
                      const productId = String(prod.id || prod.productId || prod.product_id || entityId);
                      const name = String(prod.name || prod.product_name || 'صنف جديد');
                      const barcode = prod.barcode ? String(prod.barcode) : null;
                      const sku = prod.sku ? String(prod.sku) : null;
                      const costCents = Number(prod.cost_price_cents !== undefined ? prod.cost_price_cents : (prod.cost_price ? prod.cost_price * 100 : (prod.costPrice ? prod.costPrice * 100 : 0))) || 0;
                      const sellingCents = Number(prod.selling_price_cents !== undefined ? prod.selling_price_cents : (prod.selling_price ? prod.selling_price * 100 : (prod.sellingPrice ? prod.sellingPrice * 100 : (prod.price ? prod.price * 100 : 0)))) || 0;
                      const stockQty = Number(prod.stock_quantity !== undefined ? prod.stock_quantity : (prod.stockQuantity !== undefined ? prod.stockQuantity : (prod.stock !== undefined ? prod.stock : 0))) || 0;
                      const minStock = Number(prod.min_stock_alert !== undefined ? prod.min_stock_alert : (prod.minStockAlert !== undefined ? prod.minStockAlert : 5)) || 5;
                      const unit = String(prod.unit || 'قطعة');
                      const isActive = prod.is_active !== undefined ? (prod.is_active ? 1 : 0) : 1;

                      await client.query(`
                        INSERT INTO cloud_products (
                          org_id, store_id, store_token, device_id, product_id_local, name, barcode, sku,
                          cost_price_cents, selling_price_cents, stock_quantity, min_stock_alert, unit, is_active, created_at, updated_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
                        ON CONFLICT (store_token, product_id_local) DO UPDATE SET
                          name = EXCLUDED.name,
                          barcode = EXCLUDED.barcode,
                          sku = EXCLUDED.sku,
                          cost_price_cents = EXCLUDED.cost_price_cents,
                          selling_price_cents = EXCLUDED.selling_price_cents,
                          stock_quantity = EXCLUDED.stock_quantity,
                          min_stock_alert = EXCLUDED.min_stock_alert,
                          unit = EXCLUDED.unit,
                          is_active = EXCLUDED.is_active,
                          updated_at = NOW()
                      `, [
                        effectiveOrgId,
                        effectiveStoreId,
                        token,
                        effectiveDeviceId,
                        productId,
                        name,
                        barcode,
                        sku,
                        costCents,
                        sellingCents,
                        stockQty,
                        minStock,
                        unit,
                        isActive,
                        prod.created_at || prod.createdAt || evCreatedAt
                      ]);

                      if (stockQty > 0) {
                        await client.query(`
                          INSERT INTO cloud_inventory_movements (
                            org_id, store_id, store_token, device_id, movement_id_local, product_id, movement_type, change_quantity, reference_id, created_at
                          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                          ON CONFLICT (store_token, movement_id_local) DO NOTHING
                        `, [
                          effectiveOrgId,
                          effectiveStoreId,
                          token,
                          effectiveDeviceId,
                          `MOV_INIT_${evId}_${productId}`,
                          productId,
                          'ADJUSTMENT',
                          stockQty,
                          'OPENING_STOCK',
                          prod.created_at || prod.createdAt || evCreatedAt
                        ]);
                      }
                    } else if (evType === 'INVENTORY_ADJUSTED' || entityType === 'INVENTORY_ADJUSTMENT') {
                      const adj = evPayload.adjustment || evPayload;
                      const productId = String(adj.product_id || adj.productId || entityId);
                      const newStock = Number(adj.new_stock !== undefined ? adj.new_stock : (adj.newStock !== undefined ? adj.newStock : (adj.stock_quantity !== undefined ? adj.stock_quantity : (adj.stockQuantity || 0)))) || 0;
                      const diffQty = Number(adj.difference !== undefined ? adj.difference : (adj.difference_quantity !== undefined ? adj.difference_quantity : (adj.change_quantity !== undefined ? adj.change_quantity : (adj.changeQuantity || 0)))) || 0;
                      const reason = String(adj.reason || 'تسوية جردية');

                      await client.query(`
                        UPDATE cloud_products
                        SET stock_quantity = $1, updated_at = NOW()
                        WHERE store_token = $2 AND org_id = $3 AND store_id = $4 AND product_id_local = $5
                      `, [newStock, token, effectiveOrgId, effectiveStoreId, productId]);

                      await client.query(`
                        INSERT INTO cloud_inventory_movements (
                          org_id, store_id, store_token, device_id, movement_id_local, product_id, movement_type, change_quantity, reference_id, created_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                        ON CONFLICT (store_token, movement_id_local) DO NOTHING
                      `, [
                        effectiveOrgId,
                        effectiveStoreId,
                        token,
                        effectiveDeviceId,
                        `MOV_ADJ_${evId}_${productId}`,
                        productId,
                        'ADJUSTMENT',
                        diffQty,
                        reason,
                        adj.created_at || adj.createdAt || evCreatedAt
                      ]);
                    } else if (evType === 'SHIFT_OPENED' || evType === 'SHIFT_CLOSED_Z_REPORT' || entityType === 'SHIFT') {
                      const shiftObj = (evPayload && typeof evPayload === 'object') ? (evPayload.shift || evPayload) : {};
                      const shiftIdStr = String(shiftObj.shiftId || shiftObj.id || shiftObj.shift_id || (entityType === 'SHIFT' ? entityId : null) || evId);
                      const shiftNum = Number(shiftObj.shiftNumber ?? shiftObj.shift_number ?? 1) || 1;
                      const cashierIdVal = shiftObj.cashierId || shiftObj.cashier_id;
                      const cashierIdStr = cashierIdVal ? String(cashierIdVal) : null;
                      const cashierNameStr = String(shiftObj.cashierName || shiftObj.cashier_name || shiftObj.user_name || 'كاشير');
                      const openCash = Number(shiftObj.openingCashCents ?? shiftObj.opening_cash ?? shiftObj.opening_balance_cents ?? shiftObj.openingCash ?? 0) || 0;
                      const expCash = Number(shiftObj.expectedCashCents ?? shiftObj.expected_cash ?? shiftObj.expectedCash ?? 0) || 0;
                      const actCash = Number(shiftObj.actualCashCents ?? shiftObj.actual_cash ?? shiftObj.actualCash ?? 0) || 0;
                      const diffCash = Number(shiftObj.differenceCents ?? shiftObj.variance ?? shiftObj.difference ?? 0) || 0;
                      const totSales = Number(shiftObj.totalSalesCents ?? shiftObj.shift_sales_cents ?? shiftObj.cashSales ?? shiftObj.total_cash_sales ?? 0) || 0;
                      const isClosedEv = evType === 'SHIFT_CLOSED_Z_REPORT' || ['CLOSED', 'BALANCED', 'DEFICIT', 'SURPLUS'].includes(String(shiftObj.status || '').toUpperCase());
                      const statusStr = isClosedEv ? 'CLOSED' : String(shiftObj.status || 'OPEN');
                      const openedAtStr = shiftObj.openedAt || shiftObj.opened_at || evCreatedAt;
                      const closedAtStr = shiftObj.closedAt || shiftObj.closed_at || (evType === 'SHIFT_CLOSED_Z_REPORT' ? new Date().toISOString() : null);

                      await client.query(`
                        INSERT INTO cloud_shifts (
                          org_id, store_id, store_token, device_id, shift_id_local, shift_number, cashier_id, cashier_name,
                          opening_cash_cents, expected_cash_cents, actual_cash_cents, difference_cents,
                          total_sales_cents, total_returns_cents, status, opened_at, closed_at, synced_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, NOW())
                        ON CONFLICT (store_token, device_id, shift_id_local) DO UPDATE SET
                          expected_cash_cents = EXCLUDED.expected_cash_cents,
                          actual_cash_cents = EXCLUDED.actual_cash_cents,
                          difference_cents = EXCLUDED.difference_cents,
                          total_sales_cents = EXCLUDED.total_sales_cents,
                          status = EXCLUDED.status,
                          closed_at = EXCLUDED.closed_at,
                          synced_at = NOW()
                      `, [
                        effectiveOrgId,
                        effectiveStoreId,
                        token,
                        effectiveDeviceId,
                        shiftIdStr,
                        shiftNum,
                        cashierIdStr,
                        cashierNameStr,
                        openCash,
                        expCash,
                        actCash,
                        diffCash,
                        totSales,
                        0,
                        statusStr,
                        openedAtStr,
                        closedAtStr
                      ]);
                    } else if (evType === 'CASH_MOVEMENT' || entityType === 'CASH_TRANSACTION') {
                      const cashTx = (evPayload && typeof evPayload === 'object') ? (evPayload.movement || evPayload) : {};
                      const moveId = String(cashTx.id || cashTx.movementId || evId);
                      const shiftIdRef = cashTx.shift_id || cashTx.shiftId ? String(cashTx.shift_id || cashTx.shiftId) : null;
                      const moveType = String(cashTx.type || cashTx.movementType || 'DEPOSIT');
                      const amountCents = Number(cashTx.amountCents ?? cashTx.amount ?? 0) || 0;
                      const reasonStr = String(cashTx.reason || cashTx.description || '');
                      const createdByStr = String(cashTx.created_by || cashTx.createdBy || cashTx.user_name || 'كاشير');
                      const createdAtStr = cashTx.created_at || cashTx.createdAt || evCreatedAt;

                      await client.query(`
                        INSERT INTO cloud_cash_movements (
                          org_id, store_id, store_token, device_id, movement_id_local, shift_id_local, movement_type, amount_cents, reason, created_by, created_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                        ON CONFLICT (store_token, device_id, movement_id_local) DO NOTHING
                      `, [
                        effectiveOrgId,
                        effectiveStoreId,
                        token,
                        effectiveDeviceId,
                        moveId,
                        shiftIdRef,
                        moveType,
                        amountCents,
                        reasonStr,
                        createdByStr,
                        createdAtStr
                      ]);
                    }
                  } else {
                    // Duplicate/already processed event
                    duplicateEventIds.push(evId);
                  }
                }

                // 3. Monotonic Device Sequence Update
                await client.query(`
                  INSERT INTO cloud_device_sequences (store_token, device_id, last_sequence_number, last_seen_at)
                  VALUES ($1, $2, $3, NOW())
                  ON CONFLICT (store_token, device_id)
                  DO UPDATE SET last_sequence_number = GREATEST(cloud_device_sequences.last_sequence_number, EXCLUDED.last_sequence_number), last_seen_at = NOW()
                `, [token, effectiveDeviceId, sequenceNumber]);

                // 4. Record to Universal Idempotency Ledger
                if (idempotencyKey) {
                  const ackPayload = {
                    processedEventIds: [...committedEventIds, ...duplicateEventIds],
                    committedCount: committedEventIds.length,
                    duplicateCount: duplicateEventIds.length,
                    serverTime: new Date().toISOString()
                  };
                  await client.query(`
                    INSERT INTO executed_operations_ledger (
                      org_id, store_id, device_id, idempotency_key, operation_type, entity_id, response_payload, executed_at
                    ) VALUES ($1, $2, $3, $4, 'SYNC_BATCH', $5, $6, NOW())
                    ON CONFLICT (org_id, idempotency_key) DO NOTHING
                  `, [effectiveOrgId, effectiveStoreId, effectiveDeviceId, idempotencyKey, token, JSON.stringify(ackPayload)]);
                }

                return {
                  processedEventIds: [...committedEventIds, ...duplicateEventIds],
                  committedCount: committedEventIds.length,
                  duplicateCount: duplicateEventIds.length
                };
              });
            } catch (pgCommitErr) {
              if (pgCommitErr.statusCode) {
                return res.status(pgCommitErr.statusCode).json({
                  success: false,
                  error: pgCommitErr.message,
                  code: pgCommitErr.code || 'UNAUTHORIZED'
                });
              }
              console.error('[PostgreSQL Commit Failed - Refusing ACK to Outbox]:', pgCommitErr.message);
              // STRICT INVARIANT: If PostgreSQL fails, return HTTP 503 so Outbox remains PENDING
              return res.status(503).json({
                success: false,
                error: 'PostgreSQL database commit failed. Outbox must retry.',
                details: pgCommitErr.message
              });
            }

            // Update Redis Read Cache Projection
            for (const evId of dbResult.processedEventIds) {
              markIdempotencyProcessed(token, deviceId, evId).catch(() => {});
            }

            if (dbResult.committedCount > 0) {
              if (redis) {
                try { await redis.del(`snapshot:${token}`); } catch {}
              }
              cloudSnapshots.delete(token);
            }

            const deviceRecord = {
              token,
              deviceId,
              machineId: deviceId,
              storeName,
              idempotencyKey,
              sequenceNumber,
              snapshot: snapshot || {},
              lastSync: new Date().toISOString(),
              lastIp: ip,
              storageTier: 'POSTGRESQL_DURABLE'
            };
            const aggregatedRecord = await saveDeviceSnapshotAndAggregate(token, deviceId, deviceRecord);

            return res.status(200).json({
              success: true,
              processedEventIds: dbResult.processedEventIds,
              committedCount: dbResult.committedCount,
              duplicateCount: dbResult.duplicateCount,
              serverTime: new Date().toISOString(),
              data: aggregatedRecord
            });
          }

          // ═══════════════════════════════════════════════════════════════════
          // TIER 2: REDIS / IN-MEMORY FALLBACK (Dev/Preview Environment Only)
          // ═══════════════════════════════════════════════════════════════════
          const processedEventIds = [];
          const rejectedEventIds = [];

          for (const ev of incomingEvents) {
            const evId = ev.eventId || ev.id;
            if (!evId) continue;

            const alreadyHandled = await isIdempotencyProcessed(token, deviceId, evId);
            if (alreadyHandled) {
              processedEventIds.push(evId);
              continue;
            }

            try {
              await markIdempotencyProcessed(token, deviceId, evId);
              processedEventIds.push(evId);
            } catch (err) {
              rejectedEventIds.push(evId);
            }
          }

          const lastSeq = await getDeviceSequence(token, deviceId);
          const isStaleSequence = sequenceNumber > 0 && lastSeq > 0 && sequenceNumber < lastSeq;

          if (isStaleSequence && snapshot) {
            const currentAggregated = await getPersistedSnapshot(token);
            return res.status(200).json({
              success: true,
              staleSequenceIgnored: true,
              processedEventIds,
              rejectedEventIds,
              serverTime: new Date().toISOString(),
              data: currentAggregated,
              message: `تم استيعاب الأحداث وتجاهل اللقطة الأقدم (Seq ${sequenceNumber} < ${lastSeq})`
            });
          }

          if (sequenceNumber >= lastSeq) {
            await setDeviceSequence(token, deviceId, sequenceNumber);
          }

          const deviceRecord = {
            token,
            deviceId,
            machineId: deviceId,
            storeName,
            idempotencyKey,
            sequenceNumber,
            snapshot: snapshot || {},
            lastSync: new Date().toISOString(),
            lastIp: ip,
          };

          const aggregatedRecord = await saveDeviceSnapshotAndAggregate(token, deviceId, deviceRecord);

          return res.status(200).json({
            success: true,
            processedEventIds,
            rejectedEventIds,
            serverTime: new Date().toISOString(),
            data: aggregatedRecord
          });
        } catch (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
      });
      return;
    }


    // 11. GET /api/sync, /api/cloud/data & /api/data (Mobile Read-Only Pull with Strict Cache-Busting)
    if ((pathname === '/api/sync' || pathname === '/api/cloud/data' || pathname === '/api/cloud/sync' || pathname === '/api/data' || pathname === '/api/v1/mobile/dashboard') && req.method === 'GET') {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      res.setHeader('Surrogate-Control', 'no-store');

      const token = (url.searchParams.get('token') || '').trim();
      if (!token) {
        return res.status(400).json({
          success: false,
          error: 'TOKEN_REQUIRED',
          message: 'store_token or pairing token is required.'
        });
      }
      const requestedShiftId = (url.searchParams.get('shift_id') || url.searchParams.get('shift') || '').trim() || null;

      let storeData = await getPersistedSnapshot(token, requestedShiftId);
      if (!storeData) {
        return res.status(404).json({
          success: false,
          error: 'لم يتم العثور على بيانات لهذا الرمز. تأكد من أن جهاز الكاشير متصل وقام بالمزامنة أولاً.'
        });
      }

      return res.status(200).json({
        success: true,
        readOnly: true,
        token: storeData.token,
        machineId: storeData.machineId,
        storeName: storeData.storeName,
        snapshot: storeData.snapshot || storeData,
        data: storeData,
        lastSync: storeData.lastSync,
        serverTime: new Date().toISOString()
      });
    }

    // 11b. GET /api/v1/history/invoices & /api/history/invoices (Durable Paginated Historical Invoices API)
    if ((pathname === '/api/v1/history/invoices' || pathname === '/api/history/invoices') && req.method === 'GET') {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');

      const storeToken = (url.searchParams.get('store_token') || url.searchParams.get('token') || '').trim();
      if (!storeToken) {
        return res.status(400).json({ success: false, error: 'store_token parameter is required' });
      }

      const pool = db.getPool();
      if (!pool) {
        return res.status(503).json({
          success: false,
          error: 'PostgreSQL database is required for historical invoice querying but is currently unavailable.',
          code: 'DATABASE_UNAVAILABLE'
        });
      }

      try {
        const auth = await resolveCloudTenantAuth(pool, { token: storeToken, isMobileReadOnly: true });
        if (!auth.authorized) {
          return res.status(auth.status).json({ success: false, error: auth.error, code: auth.code });
        }

        const rawPage = parseInt(url.searchParams.get('page') || '1', 10);
        const rawLimit = parseInt(url.searchParams.get('limit') || '50', 10);
        const page = isNaN(rawPage) || rawPage < 1 ? 1 : rawPage;
        const limit = isNaN(rawLimit) || rawLimit < 1 ? 50 : Math.min(rawLimit, 100); // Strict clamp max 100
        const offset = (page - 1) * limit;

        const startDate = url.searchParams.get('startDate') || url.searchParams.get('from');
        const endDate = url.searchParams.get('endDate') || url.searchParams.get('to');
        const includeItems = url.searchParams.get('includeItems') === 'true' || url.searchParams.get('include_items') === 'true';
        const invoiceIdFilter = (url.searchParams.get('invoice_id') || url.searchParams.get('id') || url.searchParams.get('invoice_number') || '').trim();

        const whereClauses = ['org_id = $1 AND store_id = $2 AND store_token = $3'];
        const queryParams = [auth.orgId, auth.storeId, auth.storeToken];
        let pIdx = 4;

        if (invoiceIdFilter) {
          whereClauses.push(`(invoice_id_local = $${pIdx} OR invoice_number = $${pIdx})`);
          queryParams.push(invoiceIdFilter);
          pIdx++;
        }

        if (startDate) {
          const sDate = new Date(startDate);
          if (!isNaN(sDate.getTime())) {
            whereClauses.push(`created_at >= $${pIdx}`);
            queryParams.push(sDate.toISOString());
            pIdx++;
          }
        }

        if (endDate) {
          const eDate = new Date(endDate);
          if (!isNaN(eDate.getTime())) {
            if (endDate.length === 10) {
              eDate.setUTCHours(23, 59, 59, 999); // Inclusive end of day for YYYY-MM-DD
            }
            whereClauses.push(`created_at <= $${pIdx}`);
            queryParams.push(eDate.toISOString());
            pIdx++;
          }
        }

        const whereSql = whereClauses.join(' AND ');

        // 1. Get total record count for pagination metadata
        const countRes = await pool.query(`SELECT COUNT(*) as total FROM cloud_invoices WHERE ${whereSql}`, queryParams);
        const total = Number(countRes.rows?.[0]?.total) || 0;
        const totalPages = total > 0 ? Math.ceil(total / limit) : 0;

        // 2. Query paginated invoices with deterministic ordering
        const fetchParams = [...queryParams, limit, offset];
        const invRes = await pool.query(`
          SELECT 
            id,
            store_token,
            device_id,
            invoice_id_local,
            invoice_number,
            shift_id_local,
            cashier_name,
            customer_id,
            customer_name,
            subtotal_cents,
            discount_cents,
            final_amount_cents,
            paid_amount_cents,
            change_amount_cents,
            payment_method,
            status,
            created_at,
            synced_at
          FROM cloud_invoices
          WHERE ${whereSql}
          ORDER BY created_at DESC, id DESC
          LIMIT $${pIdx} OFFSET $${pIdx + 1}
        `, fetchParams);

        let invoices = invRes.rows || [];

        // 3. Optional batch loading of line items (Single IN query, zero N+1)
        if (includeItems && invoices.length > 0) {
          const invLocalIds = invoices.map(i => i.invoice_id_local);
          const itemsRes = await pool.query(`
            SELECT 
              invoice_id_local,
              product_id,
              product_name,
              barcode,
              unit_cost_cents,
              unit_price_cents,
              quantity,
              subtotal_cents
            FROM cloud_invoice_items
            WHERE store_token = $1 AND invoice_id_local = ANY($2::text[])
          `, [storeToken, invLocalIds]);

          const itemsMap = new Map();
          for (const item of itemsRes.rows || []) {
            if (!itemsMap.has(item.invoice_id_local)) {
              itemsMap.set(item.invoice_id_local, []);
            }
            itemsMap.get(item.invoice_id_local).push(item);
          }

          invoices = invoices.map(inv => ({
            ...inv,
            items: itemsMap.get(inv.invoice_id_local) || []
          }));
        }

        return res.status(200).json({
          success: true,
          data: invoices,
          pagination: {
            page,
            limit,
            total,
            totalPages
          }
        });
      } catch (err) {
        console.error('[Historical Invoices API Error]:', err.message);
        return res.status(500).json({ success: false, error: err.message });
      }
    }


    // 12. POST /api/cloud/pair (Validate or initialize token)
    if (pathname === '/api/cloud/pair' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const { token, storeName, machineId } = JSON.parse(body);
          if (!token) {
            return res.status(400).json({ success: false, error: 'Token is required' });
          }

          if (!cloudSnapshots.has(token)) {
            cloudSnapshots.set(token, {
              token,
              machineId: machineId || '',
              storeName: storeName || 'أمان كاشير',
              snapshot: {
                salesSummary: { todayTotalCents: 0, todayInvoiceCount: 0, averageInvoiceCents: 0 },
                recentInvoices: [],
                lowStockProducts: [],
                activeShift: null,
                paymentBreakdown: { cashCents: 0, cardCents: 0, creditCents: 0 }
              },
              lastSync: new Date().toISOString(),
              lastIp: ip,
            });
          }

          return res.status(200).json({ success: true, token, storeName });
        } catch (err) {
          return res.status(500).json({ success: false, error: err.message });
        }
      });
      return;
    }

    // =========================================================================
    // PHASE 2B: AUTHENTICATION & SESSIONS API ENDPOINTS (/api/v2/auth/*)
    // =========================================================================

    // POST /api/v2/auth/login
    if (pathname === '/api/v2/auth/login' && req.method === 'POST') {
      const rateLimitCheck = await checkLoginRateLimit(ip);
      if (!rateLimitCheck.allowed) {
        res.setHeader('Retry-After', String(rateLimitCheck.retryAfterSeconds));
        return res.status(429).json({
          success: false,
          error: 'RATE_LIMIT_EXCEEDED',
          message: `Too many login attempts from this IP. Please try again in ${rateLimitCheck.retryAfterSeconds} seconds.`,
          retryAfterSeconds: rateLimitCheck.retryAfterSeconds
        });
      }
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const payload = JSON.parse(body || '{}');
          const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const pool = db.getPool();
          const result = await auth.loginUser(pool, {
            email: payload.email,
            password: payload.password,
            orgHint: payload.orgId || payload.orgHint,
            ip,
            userAgent,
            correlationId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      });
      return;
    }

    // POST /api/v2/auth/refresh
    if (pathname === '/api/v2/auth/refresh' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const payload = JSON.parse(body || '{}');
          const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const pool = db.getPool();
          const result = await auth.refreshSession(pool, {
            sessionId: payload.sessionId,
            rawRefreshToken: payload.refreshToken,
            ip,
            userAgent,
            correlationId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      });
      return;
    }

    // POST /api/v2/auth/logout
    if (pathname === '/api/v2/auth/logout' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const result = await auth.logoutUser(pool, {
            sessionId: authCheck.user.sessionId,
            userId: authCheck.user.userId,
            orgId: authCheck.user.orgId,
            ip,
            userAgent,
            correlationId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      });
      return;
    }

    // POST /api/v2/auth/revoke-session
    if (pathname === '/api/v2/auth/revoke-session' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const payload = JSON.parse(body || '{}');
          const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const result = await auth.revokeSession(pool, {
            targetSessionId: payload.targetSessionId,
            orgId: authCheck.user.orgId,
            callerUserId: authCheck.user.userId,
            reason: payload.reason || 'USER_REVOKED',
            ip,
            userAgent,
            correlationId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      });
      return;
    }

    // POST /api/v2/auth/change-password
    if (pathname === '/api/v2/auth/change-password' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const payload = JSON.parse(body || '{}');
          const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const result = await auth.changePassword(pool, {
            userId: authCheck.user.userId,
            orgId: authCheck.user.orgId,
            currentPassword: payload.currentPassword,
            newPassword: payload.newPassword,
            ip,
            userAgent,
            correlationId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      });
      return;
    }

    // GET /api/v2/auth/me
    if (pathname === '/api/v2/auth/me' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        return res.status(200).json({ success: true, user: authCheck.user });
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // =========================================================================
    // PHASE 2C-2C: STORE API ENDPOINTS & STORE-SCOPED AUTHORIZATION (/api/v2/stores/*)
    // =========================================================================

    // 1. GET /api/v2/stores — List accessible stores
    if (pathname === '/api/v2/stores' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        if (!rbac.hasPermission(authCheck.user.role, 'stores.read')) {
          return res.status(403).json({ success: false, error: 'PERMISSION_DENIED', message: 'You lack stores.read permission.' });
        }
        const stores = await storeScope.getUserAccessibleStores(pool, authCheck.user);
        return res.status(200).json({ success: true, stores });
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 2. POST /api/v2/stores — Create new store
    if (pathname === '/api/v2/stores' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const payload = JSON.parse(body || '{}');
          const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const result = await storeScope.createStore(pool, {
            callerActor: authCheck.user,
            storeName: payload.storeName || payload.store_name,
            storeId: payload.storeId || payload.store_id,
            ip,
            userAgent,
            correlationId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      });
      return;
    }

    // Dynamic Store ID route matcher (/api/v2/stores/:storeId and subroutes)
    const storeSubrouteMatch = pathname.match(/^\/api\/v2\/stores\/([A-Za-z0-9_-]+)(?:\/(suspend|activate|decommission|users|access\/grant|access\/revoke))?$/);
    if (storeSubrouteMatch) {
      const targetStoreId = storeSubrouteMatch[1];
      const action = storeSubrouteMatch[2] || '';

      // 3. GET /api/v2/stores/:storeId — Get store details
      if (!action && req.method === 'GET') {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const result = await storeScope.getStoreDetails(pool, {
            callerActor: authCheck.user,
            targetStoreId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      }

      // 4. PUT / PATCH /api/v2/stores/:storeId — Update store
      if (!action && (req.method === 'PUT' || req.method === 'PATCH')) {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const payload = JSON.parse(body || '{}');
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await storeScope.updateStore(pool, {
              callerActor: authCheck.user,
              targetStoreId,
              storeName: payload.storeName || payload.store_name,
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }

      // 5. POST /api/v2/stores/:storeId/suspend — Suspend store
      if (action === 'suspend' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await storeScope.setStoreStatus(pool, {
              callerActor: authCheck.user,
              targetStoreId,
              newStatus: 'SUSPENDED',
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }

      // 6. POST /api/v2/stores/:storeId/activate — Activate store
      if (action === 'activate' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await storeScope.setStoreStatus(pool, {
              callerActor: authCheck.user,
              targetStoreId,
              newStatus: 'ACTIVE',
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }

      // 7. POST /api/v2/stores/:storeId/decommission — Decommission store
      if (action === 'decommission' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await storeScope.setStoreStatus(pool, {
              callerActor: authCheck.user,
              targetStoreId,
              newStatus: 'DECOMMISSIONED',
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }

      // 8. GET /api/v2/stores/:storeId/users — List store users
      if (action === 'users' && req.method === 'GET') {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const result = await storeScope.getStoreUsers(pool, {
            callerActor: authCheck.user,
            targetStoreId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      }

      // 9. POST /api/v2/stores/:storeId/access/grant — Grant user access
      if (action === 'access/grant' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const payload = JSON.parse(body || '{}');
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await storeScope.grantStoreAccess(pool, {
              callerActor: authCheck.user,
              targetUserId: payload.userId || payload.targetUserId,
              targetStoreId,
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }

      // 10. POST /api/v2/stores/:storeId/access/revoke — Revoke user access
      if (action === 'access/revoke' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const payload = JSON.parse(body || '{}');
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await storeScope.revokeStoreAccess(pool, {
              callerActor: authCheck.user,
              targetUserId: payload.userId || payload.targetUserId,
              targetStoreId,
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }
    }

    // =========================================================================
    // PHASE 2C-2D: ORGANIZATION SETTINGS & CLOUD USER MANAGEMENT APIs (/api/v2/org/*, /api/v2/users/*)
    // =========================================================================

    // 1. GET /api/v2/org — Get Organization details & settings
    if (pathname === '/api/v2/org' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        const result = await userOrgScope.getOrganizationDetails(pool, {
          callerActor: authCheck.user
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 2. PUT / PATCH /api/v2/org — Update Organization settings
    if (pathname === '/api/v2/org' && (req.method === 'PUT' || req.method === 'PATCH')) {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const payload = JSON.parse(body || '{}');
          const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const result = await userOrgScope.updateOrganizationDetails(pool, {
            callerActor: authCheck.user,
            orgName: payload.orgName || payload.org_name,
            ip,
            userAgent,
            correlationId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      });
      return;
    }

    // 3. GET /api/v2/users — List organization users
    if (pathname === '/api/v2/users' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        const roleFilter = url.searchParams.get('role');
        const statusFilter = url.searchParams.get('status');
        const search = url.searchParams.get('search');
        const result = await userOrgScope.listUsers(pool, {
          callerActor: authCheck.user,
          roleFilter,
          statusFilter,
          search
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 4. POST /api/v2/users — Create user
    if (pathname === '/api/v2/users' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const payload = JSON.parse(body || '{}');
          const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const result = await userOrgScope.createUser(pool, {
            callerActor: authCheck.user,
            email: payload.email,
            password: payload.password,
            fullName: payload.fullName || payload.full_name,
            role: payload.role,
            status: payload.status,
            ip,
            userAgent,
            correlationId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      });
      return;
    }

    // 5. Dynamic User ID route matcher (/api/v2/users/:userId and subroutes)
    const userSubrouteMatch = pathname.match(/^\/api\/v2\/users\/([A-Za-z0-9_-]+)(?:\/(activate|deactivate|stores(?:\/(assign|unassign))?))?$/);
    if (userSubrouteMatch) {
      const targetUserId = userSubrouteMatch[1];
      const action = userSubrouteMatch[2] || '';

      // GET /api/v2/users/:userId — User details
      if (!action && req.method === 'GET') {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const result = await userOrgScope.getUserDetails(pool, {
            callerActor: authCheck.user,
            targetUserId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      }

      // PUT / PATCH /api/v2/users/:userId — Update user
      if (!action && (req.method === 'PUT' || req.method === 'PATCH')) {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const payload = JSON.parse(body || '{}');
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await userOrgScope.updateUser(pool, {
              callerActor: authCheck.user,
              targetUserId,
              fullName: payload.fullName || payload.full_name,
              role: payload.role,
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }

      // POST /api/v2/users/:userId/activate — Activate user
      if (action === 'activate' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await userOrgScope.setUserStatus(pool, {
              callerActor: authCheck.user,
              targetUserId,
              newStatus: 'ACTIVE',
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }

      // POST /api/v2/users/:userId/deactivate — Deactivate user (revokes active sessions)
      if (action === 'deactivate' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await userOrgScope.setUserStatus(pool, {
              callerActor: authCheck.user,
              targetUserId,
              newStatus: 'DEACTIVATED',
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }

      // GET /api/v2/users/:userId/stores — List assigned stores
      if (action === 'stores' && req.method === 'GET') {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const result = await userOrgScope.getUserAssignedStores(pool, {
            callerActor: authCheck.user,
            targetUserId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      }

      // POST /api/v2/users/:userId/stores/assign — Assign store access
      if (action === 'stores/assign' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const payload = JSON.parse(body || '{}');
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await userOrgScope.assignUserStore(pool, {
              callerActor: authCheck.user,
              targetUserId,
              targetStoreId: payload.storeId || payload.targetStoreId || payload.store_id,
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }

      // POST /api/v2/users/:userId/stores/unassign — Unassign store access
      if (action === 'stores/unassign' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const payload = JSON.parse(body || '{}');
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await userOrgScope.unassignUserStore(pool, {
              callerActor: authCheck.user,
              targetUserId,
              targetStoreId: payload.storeId || payload.targetStoreId || payload.store_id,
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }
    }

    // =========================================================================
    // PHASE 2E-1: DEVICE LIFECYCLE & POS TERMINAL MANAGEMENT APIs (/api/v2/devices/*)
    // =========================================================================

    // 1. GET /api/v2/devices — List accessible POS devices
    if (pathname === '/api/v2/devices' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        const storeIdFilter = url.searchParams.get('store_id') || url.searchParams.get('storeId');
        const statusFilter = url.searchParams.get('status');
        const search = url.searchParams.get('search');
        const result = await deviceScope.listDevices(pool, {
          callerActor: authCheck.user,
          storeIdFilter,
          statusFilter,
          search
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // Dynamic Device ID route matcher (/api/v2/devices/:deviceId and subroutes)
    const deviceSubrouteMatch = pathname.match(/^\/api\/v2\/devices\/([A-Za-z0-9_-]+)(?:\/(revoke|transfer))?$/);
    if (deviceSubrouteMatch) {
      const targetDeviceId = deviceSubrouteMatch[1];
      const action = deviceSubrouteMatch[2] || '';

      // 2. GET /api/v2/devices/:deviceId — Get device details
      if (!action && req.method === 'GET') {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const targetStoreId = url.searchParams.get('store_id') || url.searchParams.get('storeId');
          const result = await deviceScope.getDeviceDetails(pool, {
            callerActor: authCheck.user,
            targetDeviceId,
            targetStoreId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      }

      // 3. POST /api/v2/devices/:deviceId/revoke — Revoke device terminal
      if (action === 'revoke' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const payload = JSON.parse(body || '{}');
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await deviceScope.revokeDevice(pool, {
              callerActor: authCheck.user,
              targetDeviceId,
              targetStoreId: payload.storeId || payload.targetStoreId || payload.store_id,
              reason: payload.reason,
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }

      // 4. POST /api/v2/devices/:deviceId/transfer — Authorize hardware replacement transfer
      if (action === 'transfer' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const payload = JSON.parse(body || '{}');
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await deviceScope.transferDevice(pool, {
              callerActor: authCheck.user,
              targetDeviceId,
              targetStoreId: payload.storeId || payload.targetStoreId || payload.store_id,
              newMachineId: payload.newMachineId || payload.new_machine_id || payload.machineId,
              reason: payload.reason,
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }
    }

    // =========================================================================
    // PHASE 2E-2: DEVICE PAIRING LIFECYCLE APIs (/api/v2/pairings/*)
    // =========================================================================

    // 1. POST /api/v2/pairings/generate — Generate single-use pairing code
    if (pathname === '/api/v2/pairings/generate' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const pool = db.getPool();
          const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
          if (!authCheck.authenticated) {
            return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
          }
          const payload = JSON.parse(body || '{}');
          const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const result = await pairingScope.generatePairingCode(pool, {
            callerActor: authCheck.user,
            storeId: payload.storeId || payload.store_id,
            deviceId: payload.deviceId || payload.device_id,
            ttlMinutes: payload.ttlMinutes || payload.ttl_minutes,
            ip,
            userAgent,
            correlationId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      });
      return;
    }

    // 2. POST /api/v2/pairings/claim — POS Terminal Claims Pairing (One-Time Consumption)
    if (pathname === '/api/v2/pairings/claim' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const pool = db.getPool();
          const payload = JSON.parse(body || '{}');
          const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
          const userAgent = req.headers['user-agent'] || 'Unknown';
          const result = await pairingScope.claimPairingCode(pool, {
            pairingCode: payload.pairingCode || payload.pairing_code || payload.code,
            machineId: payload.machineId || payload.machine_id,
            deviceName: payload.deviceName || payload.device_name,
            ip,
            userAgent,
            correlationId
          });
          return res.status(result.statusCode).json(result);
        } catch (err) {
          return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
        }
      });
      return;
    }

    // 3. GET /api/v2/pairings — List pending/active pairings
    if (pathname === '/api/v2/pairings' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        const storeIdFilter = url.searchParams.get('store_id') || url.searchParams.get('storeId');
        const statusFilter = url.searchParams.get('status');
        const result = await pairingScope.listPairings(pool, {
          callerActor: authCheck.user,
          storeIdFilter,
          statusFilter
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 4. Dynamic Pairing ID route matcher (/api/v2/pairings/:pairingId/revoke)
    const pairingSubrouteMatch = pathname.match(/^\/api\/v2\/pairings\/([A-Za-z0-9_-]+)(?:\/(revoke))?$/);
    if (pairingSubrouteMatch) {
      const targetPairingId = pairingSubrouteMatch[1];
      const action = pairingSubrouteMatch[2] || '';

      if (action === 'revoke' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', async () => {
          try {
            const pool = db.getPool();
            const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
            if (!authCheck.authenticated) {
              return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
            }
            const payload = JSON.parse(body || '{}');
            const correlationId = req.headers['x-correlation-id'] || 'req_' + Date.now();
            const userAgent = req.headers['user-agent'] || 'Unknown';
            const result = await pairingScope.revokePairingCode(pool, {
              callerActor: authCheck.user,
              pairingId: targetPairingId,
              reason: payload.reason,
              ip,
              userAgent,
              correlationId
            });
            return res.status(result.statusCode).json(result);
          } catch (err) {
            return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
          }
        });
        return;
      }
    }

    // =========================================================================
    // PHASE 2E-3: ANALYTICS, INVENTORY & AUDIT TRAIL APIs
    // =========================================================================

    // 1. GET /api/v2/analytics/overview — Financial & Sales Aggregation
    if (pathname === '/api/v2/analytics/overview' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        if (!rbac.hasPermission(authCheck.user.role, rbac.PERMISSIONS.REPORTS_SALES_READ)) {
          return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'Permission reports.sales.read required.' });
        }
        const storeIdFilter = url.searchParams.get('store_id') || url.searchParams.get('storeId');
        const startDate = url.searchParams.get('startDate') || url.searchParams.get('from');
        const endDate = url.searchParams.get('endDate') || url.searchParams.get('to');
        const result = await analyticsScope.getAnalyticsOverview(pool, {
          callerActor: authCheck.user,
          storeIdFilter,
          startDate,
          endDate
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 2. GET /api/v2/analytics/invoices — Paginated Invoice Analytics
    if (pathname === '/api/v2/analytics/invoices' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        if (!rbac.hasPermission(authCheck.user.role, rbac.PERMISSIONS.REPORTS_SALES_READ)) {
          return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'Permission reports.sales.read required.' });
        }
        const storeIdFilter = url.searchParams.get('store_id') || url.searchParams.get('storeId');
        const paymentMethod = url.searchParams.get('payment_method') || url.searchParams.get('paymentMethod');
        const page = url.searchParams.get('page');
        const limit = url.searchParams.get('limit');
        const startDate = url.searchParams.get('startDate') || url.searchParams.get('from');
        const endDate = url.searchParams.get('endDate') || url.searchParams.get('to');
        const result = await analyticsScope.getInvoiceAnalytics(pool, {
          callerActor: authCheck.user,
          storeIdFilter,
          paymentMethod,
          page,
          limit,
          startDate,
          endDate
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 3. GET /api/v2/analytics/invoices/:invoiceId — Invoice details with line items
    const invoiceDetailMatch = pathname.match(/^\/api\/v2\/analytics\/invoices\/([A-Za-z0-9_-]+)$/);
    if (invoiceDetailMatch && req.method === 'GET') {
      try {
        const targetInvoiceId = invoiceDetailMatch[1];
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        if (!rbac.hasPermission(authCheck.user.role, rbac.PERMISSIONS.REPORTS_SALES_READ)) {
          return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'Permission reports.sales.read required.' });
        }
        const storeIdFilter = url.searchParams.get('store_id') || url.searchParams.get('storeId');
        const result = await analyticsScope.getInvoiceDetails(pool, {
          callerActor: authCheck.user,
          invoiceId: targetInvoiceId,
          storeIdFilter
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 4. GET /api/v2/analytics/shifts — Paginated Shift Reconciliation
    if (pathname === '/api/v2/analytics/shifts' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        if (!rbac.hasPermission(authCheck.user.role, rbac.PERMISSIONS.REPORTS_SHIFTS_READ)) {
          return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'Permission reports.shifts.read required.' });
        }
        const storeIdFilter = url.searchParams.get('store_id') || url.searchParams.get('storeId');
        const statusFilter = url.searchParams.get('status');
        const page = url.searchParams.get('page');
        const limit = url.searchParams.get('limit');
        const startDate = url.searchParams.get('startDate') || url.searchParams.get('from');
        const endDate = url.searchParams.get('endDate') || url.searchParams.get('to');
        const result = await analyticsScope.getShiftAnalytics(pool, {
          callerActor: authCheck.user,
          storeIdFilter,
          statusFilter,
          page,
          limit,
          startDate,
          endDate
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 5. GET /api/v2/analytics/shifts/:shiftId — Shift details with cash movements
    const shiftDetailMatch = pathname.match(/^\/api\/v2\/analytics\/shifts\/([A-Za-z0-9_-]+)$/);
    if (shiftDetailMatch && req.method === 'GET') {
      try {
        const targetShiftId = shiftDetailMatch[1];
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        if (!rbac.hasPermission(authCheck.user.role, rbac.PERMISSIONS.REPORTS_SHIFTS_READ)) {
          return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'Permission reports.shifts.read required.' });
        }
        const storeIdFilter = url.searchParams.get('store_id') || url.searchParams.get('storeId');
        const result = await analyticsScope.getShiftDetails(pool, {
          callerActor: authCheck.user,
          shiftId: targetShiftId,
          storeIdFilter
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 6. GET /api/v2/inventory/overview — Product Catalog & Low-Stock Alerts
    if (pathname === '/api/v2/inventory/overview' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        if (!rbac.hasPermission(authCheck.user.role, rbac.PERMISSIONS.REPORTS_INVENTORY_READ)) {
          return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'Permission reports.inventory.read required.' });
        }
        const storeIdFilter = url.searchParams.get('store_id') || url.searchParams.get('storeId');
        const lowStockOnly = url.searchParams.get('low_stock_only') || url.searchParams.get('lowStockOnly');
        const search = url.searchParams.get('search');
        const page = url.searchParams.get('page');
        const limit = url.searchParams.get('limit');
        const result = await analyticsScope.getInventoryOverview(pool, {
          callerActor: authCheck.user,
          storeIdFilter,
          lowStockOnly,
          search,
          page,
          limit
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 7. GET /api/v2/inventory/movements — Immutable Stock Movement Ledger
    if (pathname === '/api/v2/inventory/movements' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        if (!rbac.hasPermission(authCheck.user.role, rbac.PERMISSIONS.REPORTS_INVENTORY_READ)) {
          return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'Permission reports.inventory.read required.' });
        }
        const storeIdFilter = url.searchParams.get('store_id') || url.searchParams.get('storeId');
        const productId = url.searchParams.get('product_id') || url.searchParams.get('productId');
        const movementType = url.searchParams.get('movement_type') || url.searchParams.get('movementType');
        const page = url.searchParams.get('page');
        const limit = url.searchParams.get('limit');
        const result = await analyticsScope.getInventoryMovements(pool, {
          callerActor: authCheck.user,
          storeIdFilter,
          productId,
          movementType,
          page,
          limit
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 8. GET /api/v2/audit-logs — Centralized Immutable SaaS Audit Trail
    if (pathname === '/api/v2/audit-logs' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        if (!rbac.hasPermission(authCheck.user.role, rbac.PERMISSIONS.AUDIT_READ)) {
          return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'Permission audit.read required.' });
        }
        const actorIdFilter = url.searchParams.get('actor_id') || url.searchParams.get('actorId') || url.searchParams.get('user_id') || url.searchParams.get('userId');
        const actionFilter = url.searchParams.get('action');
        const resourceTypeFilter = url.searchParams.get('resource_type') || url.searchParams.get('resourceType') || url.searchParams.get('entity_type') || url.searchParams.get('entityType');
        const resourceIdFilter = url.searchParams.get('resource_id') || url.searchParams.get('resourceId') || url.searchParams.get('entity_id') || url.searchParams.get('entityId');
        const storeIdFilter = url.searchParams.get('store_id') || url.searchParams.get('storeId');
        const page = url.searchParams.get('page');
        const limit = url.searchParams.get('limit');
        const startDate = url.searchParams.get('startDate') || url.searchParams.get('from');
        const endDate = url.searchParams.get('endDate') || url.searchParams.get('to');
        const result = await analyticsScope.getAuditLogs(pool, {
          callerActor: authCheck.user,
          actorIdFilter,
          actionFilter,
          resourceTypeFilter,
          resourceIdFilter,
          storeIdFilter,
          page,
          limit,
          startDate,
          endDate
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 8b. GET /api/v2/audit-logs/:auditId — Single Immutable Audit Log Lookup
    if (pathname.startsWith('/api/v2/audit-logs/') && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authCheck = await auth.authenticateRequest(pool, req.headers['authorization']);
        if (!authCheck.authenticated) {
          return res.status(authCheck.statusCode).json({ success: false, error: authCheck.error });
        }
        if (!rbac.hasPermission(authCheck.user.role, rbac.PERMISSIONS.AUDIT_READ)) {
          return res.status(403).json({ success: false, error: 'FORBIDDEN', message: 'Permission audit.read required.' });
        }
        const auditId = pathname.replace('/api/v2/audit-logs/', '').split('/')[0];
        const result = await analyticsScope.getAuditLogById(pool, {
          callerActor: authCheck.user,
          auditId
        });
        return res.status(result.statusCode).json(result);
      } catch (err) {
        return res.status(500).json({ success: false, error: 'INTERNAL_ERROR', message: err.message });
      }
    }

    // 9. POST /api/v2/admin/tenants — Admin Multi-Tenant Customer Onboarding
    if ((pathname === '/api/v2/admin/tenants' || pathname === '/api/v2/admin/tenants/onboard' || pathname === '/api/v1/admin/onboard') && req.method === 'POST') {
      try {
        const pool = db.getPool();
        const authResult = await authenticateAdminOrPlatformRole(req, pool);
        if (!authResult.authorized) {
          return res.status(authResult.statusCode || 401).json({ success: false, error: authResult.error, message: authResult.message });
        }

        const bodyData = await readJsonBody(req);
        const idempotencyKey = req.headers['x-idempotency-key'] || bodyData.idempotencyKey || bodyData.idempotency_key || null;

        const onboardingParams = {
          orgName: bodyData.orgName || bodyData.org_name || 'مؤسسة جديدة',
          storeName: bodyData.storeName || bodyData.store_name || 'الفرع الرئيسي',
          ownerEmail: bodyData.ownerEmail || bodyData.owner_email || 'owner@tenant.com',
          ownerName: bodyData.ownerName || bodyData.owner_name || 'مالك المتجر',
          planId: bodyData.planId || bodyData.plan_id || bodyData.plan || 'STARTER',
          deviceName: bodyData.deviceName || bodyData.device_name || 'الكاشير الرئيسي',
          idempotencyKey
        };

        const result = await onboardingService.createTenantOnboarding(pool, onboardingParams);

        // Record Audit Trail
        try {
          await auth.recordAuthAuditLog(pool, {
            orgId: result.orgId,
            actorId: authResult.actor.userId,
            actorType: 'PLATFORM_ADMIN',
            action: 'TENANT_ONBOARDED',
            resourceType: 'ORGANIZATION',
            resourceId: result.orgId,
            details: { orgName: result.orgName, storeId: result.storeId, deviceId: result.deviceId, planId: result.planId, idempotent: !!result.idempotent },
            ip
          });
        } catch (auditErr) {
          console.warn('[AuditLog Warning]: Failed to record tenant onboarding audit:', auditErr.message);
        }

        const httpStatus = result.idempotent ? 200 : 201;
        return res.status(httpStatus).json(result);
      } catch (err) {
        console.error('[ADMIN_ONBOARDING_ERROR]', err);
        return res.status(500).json({ success: false, error: 'ONBOARDING_FAILED', message: err.message });
      }
    }

    // 10. GET /api/v2/admin/tenants — List Onboarded Organizations
    if (pathname === '/api/v2/admin/tenants' && req.method === 'GET') {
      try {
        const pool = db.getPool();
        const authResult = await authenticateAdminOrPlatformRole(req, pool);
        if (!authResult.authorized) {
          return res.status(authResult.statusCode || 401).json({ success: false, error: authResult.error, message: authResult.message });
        }

        const limit = parseInt(url.searchParams.get('limit') || '50', 10);
        const offset = parseInt(url.searchParams.get('offset') || '0', 10);

        const result = await onboardingService.listTenants(pool, { limit, offset });
        return res.status(200).json(result);
      } catch (err) {
        console.error('[ADMIN_LIST_TENANTS_ERROR]', err);
        return res.status(500).json({ success: false, error: 'FETCH_TENANTS_FAILED', message: err.message });
      }
    }

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};

if (require.main === module) {
  const http = require('http');
  const PORT = process.env.PORT || 3001;
  const server = http.createServer((req, res) => {
    module.exports(req, res);
  });
  server.listen(PORT, () => {
    console.log(`\n=============================================================`);
    console.log(`🚀 سيرفر تراخيص أمان كاشير يعمل بنجاح!`);
    console.log(`🌐 لوحة الإدارة للمطور: http://localhost:${PORT}`);
    console.log(`📱 بوابة المتابعة الحية: http://localhost:${PORT}/mobile.html`);
    console.log(`=============================================================\n`);
  });
}

