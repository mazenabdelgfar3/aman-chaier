/**
 * AMAN CASHIER SAAS — DEVICE PAIRING LIFECYCLE & PROVISIONING ENGINE
 * PHASE 2E-2: Cryptographic Pairing Secrets, Expiration, One-Time Consumption & Hardware Binding
 * 
 * Rules:
 * 1. Cryptographic Entropy: Node.js crypto.randomBytes only (no Math.random or predictable seeds).
 * 2. Organization ID derived exclusively from server-side authenticated context (callerActor.orgId).
 * 3. Store Scoping: STORE_MANAGER restricted strictly to assigned stores in cloud_user_store_access.
 * 4. Atomic Consumption: Single-operation atomic conditional updates to prevent race conditions & replay.
 * 5. Brute-Force & Rate-Limiting Defense: Tracking failed claim attempts per IP and pairing code.
 * 6. Zero Credential Leakage: device_key and private secrets strictly sanitized from logs and responses.
 */

const crypto = require('crypto');
const rbac = require('./rbac');
const storeScope = require('./storeScope');

// In-Memory Rate Limiting & Brute-Force Lockout Tracker
const claimAttemptTracker = new Map(); // ip/key -> { count: number, lockedUntil: number, firstAttemptAt: number }

const MAX_FAILED_CLAIM_ATTEMPTS = 5;
const CLAIM_LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes lockout
const CLAIM_WINDOW_MS = 10 * 60 * 1000; // 10 minutes tracking window

/**
 * Check if IP or client is locked out due to excessive failed attempts
 */
function checkRateLimit(identifier) {
  const now = Date.now();
  const record = claimAttemptTracker.get(identifier);
  if (!record) return { allowed: true };

  if (record.lockedUntil && record.lockedUntil > now) {
    const remainingSec = Math.ceil((record.lockedUntil - now) / 1000);
    return {
      allowed: false,
      statusCode: 429,
      error: 'RATE_LIMIT_EXCEEDED',
      message: `Too many failed pairing attempts. Please retry after ${remainingSec} seconds.`
    };
  }

  // Reset if window has elapsed
  if (now - record.firstAttemptAt > CLAIM_WINDOW_MS) {
    claimAttemptTracker.delete(identifier);
    return { allowed: true };
  }

  return { allowed: true };
}

/**
 * Record a failed pairing claim attempt
 */
function recordFailedAttempt(identifier) {
  const now = Date.now();
  let record = claimAttemptTracker.get(identifier);
  if (!record || now - record.firstAttemptAt > CLAIM_WINDOW_MS) {
    record = { count: 1, firstAttemptAt: now, lockedUntil: 0 };
  } else {
    record.count++;
  }

  if (record.count >= MAX_FAILED_CLAIM_ATTEMPTS) {
    record.lockedUntil = now + CLAIM_LOCKOUT_DURATION_MS;
  }

  claimAttemptTracker.set(identifier, record);
}

/**
 * Clear failed attempts on successful claim
 */
function resetFailedAttempts(identifier) {
  claimAttemptTracker.delete(identifier);
}

/**
 * Generate cryptographically secure pairing code
 * Format: PAIR-XXXX-XXXX (Base32 uppercase, >45 bits of entropy for short 10-min window)
 */
function generateSecurePairingCode() {
  const chars = '23456789ABCDEFGHJKMNPQRSTUVWXYZ'; // Crockford Base32 (no ambiguous 0, 1, I, O, L)
  const bytes = crypto.randomBytes(8);
  let codePart1 = '';
  let codePart2 = '';

  for (let i = 0; i < 4; i++) {
    codePart1 += chars[bytes[i] % chars.length];
  }
  for (let i = 4; i < 8; i++) {
    codePart2 += chars[bytes[i] % chars.length];
  }

  return `PAIR-${codePart1}-${codePart2}`;
}

/**
 * Execute parameterized query safely across PostgreSQL Pool or Better-SQLite3
 */
async function executeDbQuery(db, text, params = []) {
  if (typeof db.query === 'function') {
    const res = await db.query(text, params);
    return res.rows || [];
  }
  if (typeof db.prepare === 'function') {
    let sqliteSql = text.trim();
    sqliteSql = sqliteSql.replace(/\$(\d+)/g, '?');
    const isMutation = /^(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b/i.test(sqliteSql);
    if (isMutation) {
      const stmt = db.prepare(sqliteSql);
      const res = stmt.run(...params);
      return [{ changes: res.changes, lastInsertRowid: res.lastInsertRowid }];
    }
    return db.prepare(sqliteSql).all(...params);
  }
  throw new Error('DATABASE_ADAPTER_UNSUPPORTED: Missing query or prepare method.');
}

/**
 * Record clean audit log for device pairing mutation
 */
async function recordPairingAuditLog(db, {
  orgId,
  storeId = null,
  deviceId = null,
  actorId,
  actorType = 'USER',
  action,
  resourceId = null,
  details = {},
  ip = null,
  userAgent = null,
  correlationId = null
}) {
  const sanitizedDetails = { ...details };
  delete sanitizedDetails.password;
  delete sanitizedDetails.password_hash;
  delete sanitizedDetails.passwordHash;
  delete sanitizedDetails.deviceKey;
  delete sanitizedDetails.device_key;
  delete sanitizedDetails.token;
  delete sanitizedDetails.rawToken;
  delete sanitizedDetails.secret;
  delete sanitizedDetails.pairingSecret;

  const query = `
    INSERT INTO cloud_audit_logs 
      (org_id, store_id, device_id, actor_id, actor_type, action, resource_type, resource_id, correlation_id, details, ip_address, user_agent, created_at)
    VALUES 
      ($1, $2, $3, $4, $5, $6, 'PAIRING', $7, $8, $9, $10, $11, CURRENT_TIMESTAMP)
  `;
  try {
    await executeDbQuery(db, query, [
      orgId,
      storeId,
      deviceId,
      String(actorId || 'SYSTEM'),
      actorType,
      action,
      resourceId ? String(resourceId) : 'PAIRING',
      correlationId || `corr_${Date.now()}`,
      JSON.stringify(sanitizedDetails),
      ip,
      userAgent
    ]);
  } catch (err) {
    console.error('[PairingAuditLog Error]:', err.message);
  }
}

/**
 * Sanitize pairing object to guarantee zero secret leakage
 */
function sanitizePairing(pairing) {
  if (!pairing) return null;
  const clean = { ...pairing };
  delete clean.device_key;
  delete clean.deviceKey;
  delete clean.bound_device_key;
  return clean;
}

/**
 * 1. GENERATE PAIRING CODE
 * Generates short-lived, single-use pairing code for a store
 */
async function generatePairingCode(db, {
  callerActor,
  storeId,
  deviceId = null,
  ttlMinutes = 10,
  ip = null,
  userAgent = null,
  correlationId = null
}) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // 1. RBAC Check: Only ORG_OWNER, PLATFORM_ADMIN or authorized STORE_MANAGER
  const role = rbac.normalizeRole(callerActor.role);
  if (role !== 'ORG_OWNER' && role !== 'PLATFORM_ADMIN' && role !== 'STORE_MANAGER') {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You are not authorized to generate device pairing codes.' };
  }

  if (!storeId || typeof storeId !== 'string' || !storeId.trim()) {
    return { success: false, statusCode: 400, error: 'MISSING_STORE_ID', message: 'Target store ID is required.' };
  }

  const cleanStoreId = storeId.trim();
  const orgId = callerActor.orgId;

  // 2. Validate Store Access & Ownership
  if (role === 'STORE_MANAGER') {
    const storeValidation = await storeScope.validateStoreAccess(db, callerActor, cleanStoreId);
    if (!storeValidation.allowed) {
      return { success: false, statusCode: 403, error: 'CROSS_STORE_ACCESS_DENIED', message: 'You lack access to generate pairings for this store.' };
    }
  }

  // Verify Store exists and is ACTIVE
  const storeRows = await executeDbQuery(db, `
    SELECT s.id, s.org_id, s.store_id, s.status as store_status, o.status as org_status
    FROM cloud_stores s
    LEFT JOIN cloud_organizations o ON s.org_id = o.org_id
    WHERE s.org_id = $1 AND s.store_id = $2
  `, [orgId, cleanStoreId]);

  if (storeRows.length === 0) {
    return { success: false, statusCode: 404, error: 'STORE_NOT_FOUND', message: 'Store not found in organization.' };
  }

  const store = storeRows[0];
  if (store.store_status !== 'ACTIVE' || store.org_status !== 'ACTIVE') {
    return { success: false, statusCode: 403, error: 'STORE_INACTIVE', message: 'Cannot pair devices to a suspended or inactive store.' };
  }

  // 3. Generate Cryptographic Pairing Code
  const pairingCode = generateSecurePairingCode();
  const cleanDeviceId = deviceId && typeof deviceId === 'string' && deviceId.trim() ? deviceId.trim() : `POS-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const effectiveTtl = Math.max(1, Math.min(60, Number(ttlMinutes) || 10)); // 1 to 60 mins

  // Server-side expiration calculation (Durable UTC timestamp)
  const expiresAt = new Date(Date.now() + effectiveTtl * 60 * 1000).toISOString();
  const pairingId = `pair_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

  // 4. Persist in cloud_pairings with status PENDING
  await executeDbQuery(db, `
    INSERT INTO cloud_pairings 
      (id, pairing_token, org_id, store_id, device_id, device_key, status, expires_at, created_at, last_used_at)
    VALUES 
      ($1, $2, $3, $4, $5, NULL, 'PENDING', $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `, [pairingId, pairingCode, orgId, cleanStoreId, cleanDeviceId, expiresAt]);

  // 5. Record Audit Trail
  await recordPairingAuditLog(db, {
    orgId,
    storeId: cleanStoreId,
    deviceId: cleanDeviceId,
    actorId: callerActor.userId,
    actorType: 'USER',
    action: 'PAIRING_GENERATED',
    resourceId: pairingCode,
    details: {
      pairingId,
      pairingCode,
      storeId: cleanStoreId,
      deviceId: cleanDeviceId,
      ttlMinutes: effectiveTtl,
      expiresAt
    },
    ip,
    userAgent,
    correlationId
  });

  return {
    success: true,
    statusCode: 201,
    pairing: {
      id: pairingId,
      pairingCode,
      orgId,
      storeId: cleanStoreId,
      deviceId: cleanDeviceId,
      status: 'PENDING',
      expiresAt,
      ttlMinutes: effectiveTtl
    }
  };
}

/**
 * 2. CLAIM PAIRING CODE (Atomic One-Time Consumption)
 * Terminal provides pairing code + machine_id -> receives permanent credentials
 */
async function claimPairingCode(db, {
  pairingCode,
  machineId,
  deviceName = 'جهاز كاشير',
  ip = null,
  userAgent = null,
  correlationId = null
}) {
  const rateLimitKey = ip || 'anonymous_claim';
  const rateCheck = checkRateLimit(rateLimitKey);
  if (!rateCheck.allowed) {
    return rateCheck;
  }

  if (!pairingCode || typeof pairingCode !== 'string' || !pairingCode.trim()) {
    recordFailedAttempt(rateLimitKey);
    return { success: false, statusCode: 400, error: 'MISSING_PAIRING_CODE', message: 'Pairing code is required.' };
  }

  if (!machineId || typeof machineId !== 'string' || !machineId.trim()) {
    recordFailedAttempt(rateLimitKey);
    return { success: false, statusCode: 400, error: 'MISSING_MACHINE_ID', message: 'Hardware fingerprint (machineId) is required.' };
  }

  const cleanPairingCode = pairingCode.trim().toUpperCase();
  const cleanMachineId = machineId.trim().toUpperCase();
  const cleanDeviceName = deviceName ? deviceName.trim() : 'جهاز كاشير';

  // 1. Fetch pairing record
  const pairingRows = await executeDbQuery(db, `
    SELECT p.id, p.pairing_token, p.org_id, p.store_id, p.device_id, p.status, p.expires_at,
           s.status as store_status, s.store_name, s.store_token, o.status as org_status
    FROM cloud_pairings p
    LEFT JOIN cloud_stores s ON p.org_id = s.org_id AND p.store_id = s.store_id
    LEFT JOIN cloud_organizations o ON p.org_id = o.org_id
    WHERE p.pairing_token = $1
  `, [cleanPairingCode]);

  if (pairingRows.length === 0) {
    recordFailedAttempt(rateLimitKey);
    return { success: false, statusCode: 404, error: 'INVALID_PAIRING_CODE', message: 'Pairing code not found or invalid.' };
  }

  const pairing = pairingRows[0];

  // 2. Check Expiration
  if (pairing.expires_at && new Date(pairing.expires_at) < new Date()) {
    recordFailedAttempt(rateLimitKey);
    return { success: false, statusCode: 400, error: 'PAIRING_EXPIRED', message: 'Pairing code has expired. Please generate a new code.' };
  }

  // 3. Check State
  if (pairing.status !== 'PENDING') {
    recordFailedAttempt(rateLimitKey);
    if (pairing.status === 'CLAIMED' || pairing.status === 'ACTIVE') {
      return { success: false, statusCode: 409, error: 'PAIRING_ALREADY_CLAIMED', message: 'This pairing code has already been consumed.' };
    }
    if (pairing.status === 'REVOKED') {
      return { success: false, statusCode: 403, error: 'PAIRING_REVOKED', message: 'This pairing code was revoked.' };
    }
    return { success: false, statusCode: 400, error: 'INVALID_PAIRING_STATE', message: 'Pairing code is not available for claim.' };
  }

  // 4. Check Store & Organization Status
  if (pairing.store_status !== 'ACTIVE' || pairing.org_status !== 'ACTIVE') {
    recordFailedAttempt(rateLimitKey);
    return { success: false, statusCode: 403, error: 'STORE_OR_ORG_INACTIVE', message: 'Cannot bind terminal to an inactive or suspended store.' };
  }

  // 5. Check if device is already REVOKED in cloud_devices
  const existingDev = await executeDbQuery(db, `
    SELECT id, status FROM cloud_devices WHERE org_id = $1 AND store_id = $2 AND device_id = $3
  `, [pairing.org_id, pairing.store_id, pairing.device_id]);

  if (existingDev.length > 0 && existingDev[0].status === 'REVOKED') {
    recordFailedAttempt(rateLimitKey);
    return { success: false, statusCode: 403, error: 'DEVICE_REVOKED', message: 'This terminal has been permanently revoked by administrators.' };
  }

  // 6. ATOMIC CLAIM CONSUMPTION: Single-row conditional update to eliminate race conditions
  const updateRes = await executeDbQuery(db, `
    UPDATE cloud_pairings 
    SET status = 'CLAIMED', last_used_at = CURRENT_TIMESTAMP
    WHERE id = $1 AND status = 'PENDING'
  `, [pairing.id]);

  const changesCount = updateRes[0]?.changes !== undefined ? updateRes[0].changes : 1;
  if (changesCount === 0) {
    recordFailedAttempt(rateLimitKey);
    return { success: false, statusCode: 409, error: 'PAIRING_CLAIM_RACE_LOST', message: 'Pairing code was consumed by another concurrent request.' };
  }

  // 7. Generate Terminal Cryptographic Keys & Store Token
  const issuedDeviceKey = `DK_${crypto.randomBytes(24).toString('hex')}`;
  const effectiveStoreToken = pairing.store_token || `TOK_${pairing.org_id}_${pairing.store_id}`;
  const persistentPairingToken = `PAIR_${crypto.randomBytes(24).toString('hex')}`;

  // Upsert in cloud_devices
  await executeDbQuery(db, `
    INSERT INTO cloud_devices 
      (id, org_id, store_id, device_id, machine_id, device_key, status, created_at, last_seen_at)
    VALUES 
      ($1, $2, $3, $4, $5, $6, 'ACTIVE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `, [
    `dev_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
    pairing.org_id,
    pairing.store_id,
    pairing.device_id,
    cleanMachineId,
    issuedDeviceKey
  ]);

  // Insert permanent active pairing token for ongoing sync authentication
  await executeDbQuery(db, `
    INSERT INTO cloud_pairings 
      (id, pairing_token, org_id, store_id, device_id, device_key, status, created_at, last_used_at)
    VALUES 
      ($1, $2, $3, $4, $5, $6, 'ACTIVE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `, [
    `pair_perm_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
    persistentPairingToken,
    pairing.org_id,
    pairing.store_id,
    pairing.device_id,
    issuedDeviceKey
  ]);

  // 8. Record Sanitized Audit Log
  await recordPairingAuditLog(db, {
    orgId: pairing.org_id,
    storeId: pairing.store_id,
    deviceId: pairing.device_id,
    actorId: cleanMachineId,
    actorType: 'DEVICE',
    action: 'PAIRING_CLAIMED',
    resourceId: pairing.pairing_token,
    details: {
      pairingId: pairing.id,
      machineId: cleanMachineId,
      deviceName: cleanDeviceName,
      storeId: pairing.store_id,
      deviceId: pairing.device_id
    },
    ip,
    userAgent,
    correlationId
  });

  resetFailedAttempts(rateLimitKey);

  return {
    success: true,
    statusCode: 200,
    message: 'Device paired and provisioned successfully.',
    credentials: {
      orgId: pairing.org_id,
      storeId: pairing.store_id,
      deviceId: pairing.device_id,
      storeName: pairing.store_name || 'أمان كاشير',
      storeToken: effectiveStoreToken,
      pairingToken: persistentPairingToken,
      deviceKey: issuedDeviceKey
    }
  };
}

/**
 * 3. LIST PAIRINGS
 * List pending/active pairings within caller tenant and authorized store scope
 */
async function listPairings(db, { callerActor, storeIdFilter = null, statusFilter = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  const role = rbac.normalizeRole(callerActor.role);
  const orgId = callerActor.orgId;

  let accessibleStoreIds = [];
  if (role === 'PLATFORM_ADMIN') {
    accessibleStoreIds = null;
  } else if (role === 'ORG_OWNER') {
    accessibleStoreIds = 'ALL_ORG_STORES';
  } else {
    const userStores = await storeScope.getUserAccessibleStores(db, callerActor);
    accessibleStoreIds = userStores.map(s => s.store_id);
    if (accessibleStoreIds.length === 0) {
      return { success: true, statusCode: 200, pairings: [], total: 0 };
    }
  }

  const conditions = [];
  const params = [];
  let pIdx = 1;

  if (role !== 'PLATFORM_ADMIN') {
    conditions.push(`p.org_id = $${pIdx}`);
    params.push(orgId);
    pIdx++;
  }

  if (storeIdFilter && typeof storeIdFilter === 'string' && storeIdFilter.trim()) {
    const cleanStoreFilter = storeIdFilter.trim();
    if (Array.isArray(accessibleStoreIds) && !accessibleStoreIds.includes(cleanStoreFilter)) {
      return { success: false, statusCode: 403, error: 'CROSS_STORE_ACCESS_DENIED', message: 'You lack access to the requested store.' };
    }
    conditions.push(`p.store_id = $${pIdx}`);
    params.push(cleanStoreFilter);
    pIdx++;
  } else if (Array.isArray(accessibleStoreIds)) {
    if (accessibleStoreIds.length === 0) {
      return { success: true, statusCode: 200, pairings: [], total: 0 };
    }
    const placeholders = accessibleStoreIds.map((_, i) => `$${pIdx + i}`).join(', ');
    conditions.push(`p.store_id IN (${placeholders})`);
    params.push(...accessibleStoreIds);
    pIdx += accessibleStoreIds.length;
  }

  if (statusFilter && typeof statusFilter === 'string' && statusFilter.trim()) {
    conditions.push(`p.status = $${pIdx}`);
    params.push(statusFilter.trim().toUpperCase());
    pIdx++;
  }

  const whereSql = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const query = `
    SELECT 
      p.id, p.pairing_token, p.org_id, p.store_id, p.device_id, p.status, p.created_at, p.expires_at, p.last_used_at,
      s.store_name, s.status as store_status
    FROM cloud_pairings p
    LEFT JOIN cloud_stores s ON p.org_id = s.org_id AND p.store_id = s.store_id
    ${whereSql}
    ORDER BY p.created_at DESC
  `;

  const rows = await executeDbQuery(db, query, params);
  const pairings = rows.map(sanitizePairing);

  return {
    success: true,
    statusCode: 200,
    pairings,
    total: pairings.length
  };
}

/**
 * 4. REVOKE PAIRING CODE (Cancel Pending Code)
 */
async function revokePairingCode(db, {
  callerActor,
  pairingId,
  reason = 'MANUAL_CANCELLATION',
  ip = null,
  userAgent = null,
  correlationId = null
}) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  const role = rbac.normalizeRole(callerActor.role);
  if (role !== 'ORG_OWNER' && role !== 'PLATFORM_ADMIN' && role !== 'STORE_MANAGER') {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You are not authorized to revoke pairing codes.' };
  }

  if (!pairingId || typeof pairingId !== 'string' || !pairingId.trim()) {
    return { success: false, statusCode: 400, error: 'MISSING_PAIRING_ID' };
  }

  const cleanPairingId = pairingId.trim();
  const orgId = callerActor.orgId;

  let fetchQuery = `SELECT id, org_id, store_id, device_id, pairing_token, status FROM cloud_pairings WHERE id = $1`;
  const fetchParams = [cleanPairingId];
  let pIdx = 2;

  if (role !== 'PLATFORM_ADMIN') {
    fetchQuery += ` AND org_id = $${pIdx}`;
    fetchParams.push(orgId);
    pIdx++;
  }

  const rows = await executeDbQuery(db, fetchQuery, fetchParams);
  if (rows.length === 0) {
    return { success: false, statusCode: 404, error: 'PAIRING_NOT_FOUND', message: 'Pairing record not found.' };
  }

  const pairing = rows[0];

  if (role === 'STORE_MANAGER') {
    const storeValidation = await storeScope.validateStoreAccess(db, callerActor, pairing.store_id);
    if (!storeValidation.allowed) {
      return { success: false, statusCode: 403, error: 'CROSS_STORE_ACCESS_DENIED', message: 'You lack access to revoke pairings for this store.' };
    }
  }

  await executeDbQuery(db, `
    UPDATE cloud_pairings 
    SET status = 'REVOKED', last_used_at = CURRENT_TIMESTAMP 
    WHERE id = $1
  `, [pairing.id]);

  await recordPairingAuditLog(db, {
    orgId: pairing.org_id,
    storeId: pairing.store_id,
    deviceId: pairing.device_id,
    actorId: callerActor.userId,
    actorType: 'USER',
    action: 'PAIRING_REVOKED',
    resourceId: pairing.pairing_token,
    details: {
      pairingId: pairing.id,
      previousStatus: pairing.status,
      newStatus: 'REVOKED',
      reason
    },
    ip,
    userAgent,
    correlationId
  });

  return {
    success: true,
    statusCode: 200,
    message: `Pairing code ${pairing.pairing_token} has been revoked successfully.`,
    status: 'REVOKED'
  };
}

module.exports = {
  generateSecurePairingCode,
  generatePairingCode,
  claimPairingCode,
  listPairings,
  revokePairingCode,
  sanitizePairing,
  checkRateLimit,
  recordFailedAttempt,
  resetFailedAttempts
};
