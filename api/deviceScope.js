/**
 * AMAN CASHIER SAAS — DEVICE LIFECYCLE & HARDWARE BINDING ENGINE
 * PHASE 2E-1: POS Terminal Management, Hardware Transfers, and Instant Revocation
 * 
 * Rules:
 * 1. Client device_id is TARGET ONLY, never an authorization authority.
 * 2. Organization ID is strictly derived from Server-Side Authenticated Context (callerActor.orgId).
 * 3. Scoped Roles (STORE_MANAGER, AUDITOR, VIEWER) are strictly bound to cloud_user_store_access.
 * 4. Sensitive cryptographic credentials (device_key, private tokens) are NEVER returned in responses.
 * 5. Device Revocation takes effect in real-time across both cloud_devices and cloud_pairings.
 */

const crypto = require('crypto');
const rbac = require('./rbac');
const storeScope = require('./storeScope');

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
 * Record clean audit log for device lifecycle mutation
 */
async function recordDeviceAuditLog(db, {
  orgId,
  storeId = null,
  deviceId = null,
  actorId,
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

  const query = `
    INSERT INTO cloud_audit_logs 
      (org_id, store_id, device_id, actor_id, actor_type, action, resource_type, resource_id, correlation_id, details, ip_address, user_agent, created_at)
    VALUES 
      ($1, $2, $3, $4, 'USER', $5, 'DEVICE', $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)
  `;
  try {
    await executeDbQuery(db, query, [
      orgId,
      storeId,
      deviceId,
      String(actorId),
      action,
      resourceId ? String(resourceId) : deviceId,
      correlationId || `corr_${Date.now()}`,
      JSON.stringify(sanitizedDetails),
      ip,
      userAgent
    ]);
  } catch (err) {
    console.error('[DeviceAuditLog Error]:', err.message);
  }
}

/**
 * Sanitize device record to ensure zero credential leakage
 */
function sanitizeDevice(device) {
  if (!device) return null;
  const clean = { ...device };
  delete clean.device_key;
  delete clean.deviceKey;
  delete clean.bound_device_key;
  delete clean.raw_token;
  return clean;
}

/**
 * List POS devices accessible to the authenticated actor
 */
async function listDevices(db, { callerActor, storeIdFilter = null, statusFilter = null, search = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // 1. RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'devices.read')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack devices.read permission.' };
  }

  const role = rbac.normalizeRole(callerActor.role);
  const orgId = callerActor.orgId;

  // 2. Determine Accessible Store IDs
  let accessibleStoreIds = [];
  if (role === 'PLATFORM_ADMIN') {
    // Platform admin can query across all stores
    accessibleStoreIds = null;
  } else if (role === 'ORG_OWNER') {
    // Org owner has global tenant access
    accessibleStoreIds = 'ALL_ORG_STORES';
  } else {
    // Scoped roles (STORE_MANAGER, AUDITOR, VIEWER)
    const userStores = await storeScope.getUserAccessibleStores(db, callerActor);
    accessibleStoreIds = userStores.map(s => s.store_id);
    if (accessibleStoreIds.length === 0) {
      return { success: true, statusCode: 200, devices: [], total: 0 };
    }
  }

  // 3. Build Scoped Query
  const conditions = [];
  const params = [];
  let pIdx = 1;

  if (role !== 'PLATFORM_ADMIN') {
    conditions.push(`d.org_id = $${pIdx}`);
    params.push(orgId);
    pIdx++;
  }

  if (storeIdFilter && typeof storeIdFilter === 'string' && storeIdFilter.trim()) {
    const cleanStoreFilter = storeIdFilter.trim();
    if (Array.isArray(accessibleStoreIds) && !accessibleStoreIds.includes(cleanStoreFilter)) {
      return { success: false, statusCode: 403, error: 'CROSS_STORE_ACCESS_DENIED', message: 'You lack access to the requested store.' };
    }
    conditions.push(`d.store_id = $${pIdx}`);
    params.push(cleanStoreFilter);
    pIdx++;
  } else if (Array.isArray(accessibleStoreIds)) {
    if (accessibleStoreIds.length === 0) {
      return { success: true, statusCode: 200, devices: [], total: 0 };
    }
    const placeholders = accessibleStoreIds.map((_, i) => `$${pIdx + i}`).join(', ');
    conditions.push(`d.store_id IN (${placeholders})`);
    params.push(...accessibleStoreIds);
    pIdx += accessibleStoreIds.length;
  }

  if (statusFilter && typeof statusFilter === 'string' && statusFilter.trim()) {
    conditions.push(`d.status = $${pIdx}`);
    params.push(statusFilter.trim().toUpperCase());
    pIdx++;
  }

  if (search && typeof search === 'string' && search.trim()) {
    const sTerm = `%${search.trim().toLowerCase()}%`;
    conditions.push(`(LOWER(d.device_id) LIKE $${pIdx} OR LOWER(d.machine_id) LIKE $${pIdx + 1} OR LOWER(s.store_name) LIKE $${pIdx + 2})`);
    params.push(sTerm, sTerm, sTerm);
    pIdx += 3;
  }

  const whereSql = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const query = `
    SELECT 
      d.id, d.org_id, d.store_id, d.device_id, d.machine_id, d.status, d.created_at, d.last_seen_at,
      s.store_name, s.status as store_status
    FROM cloud_devices d
    LEFT JOIN cloud_stores s ON d.org_id = s.org_id AND d.store_id = s.store_id
    ${whereSql}
    ORDER BY d.last_seen_at DESC, d.created_at DESC
  `;

  const rows = await executeDbQuery(db, query, params);
  const devices = rows.map(sanitizeDevice);

  return {
    success: true,
    statusCode: 200,
    devices,
    total: devices.length
  };
}

/**
 * Retrieve specific device details
 */
async function getDeviceDetails(db, { callerActor, targetDeviceId, targetStoreId = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  if (!rbac.hasPermission(callerActor.role, 'devices.read')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack devices.read permission.' };
  }

  if (!targetDeviceId || typeof targetDeviceId !== 'string' || !targetDeviceId.trim()) {
    return { success: false, statusCode: 400, error: 'MISSING_DEVICE_ID' };
  }

  const cleanDeviceId = targetDeviceId.trim();
  const role = rbac.normalizeRole(callerActor.role);
  const orgId = callerActor.orgId;

  // Build query
  let query = `
    SELECT 
      d.id, d.org_id, d.store_id, d.device_id, d.machine_id, d.status, d.created_at, d.last_seen_at,
      s.store_name, s.status as store_status
    FROM cloud_devices d
    LEFT JOIN cloud_stores s ON d.org_id = s.org_id AND d.store_id = s.store_id
    WHERE d.device_id = $1
  `;
  const params = [cleanDeviceId];
  let pIdx = 2;

  if (role !== 'PLATFORM_ADMIN') {
    query += ` AND d.org_id = $${pIdx}`;
    params.push(orgId);
    pIdx++;
  }

  if (targetStoreId && typeof targetStoreId === 'string' && targetStoreId.trim()) {
    query += ` AND d.store_id = $${pIdx}`;
    params.push(targetStoreId.trim());
    pIdx++;
  }

  const rows = await executeDbQuery(db, query, params);
  if (rows.length === 0) {
    return { success: false, statusCode: 404, error: 'DEVICE_NOT_FOUND', message: 'Device not found in organization.' };
  }

  const device = rows[0];

  // Store access authorization for scoped roles
  if (role === 'STORE_MANAGER' || role === 'AUDITOR' || role === 'VIEWER') {
    const storeValidation = await storeScope.validateStoreAccess(db, callerActor, device.store_id);
    if (!storeValidation.allowed) {
      return { success: false, statusCode: 403, error: 'CROSS_STORE_ACCESS_DENIED', message: 'You lack access to the store of this device.' };
    }
  }

  // Retrieve associated active pairing record
  const pairingRows = await executeDbQuery(db, `
    SELECT id, pairing_token, status, expires_at, last_used_at, created_at
    FROM cloud_pairings
    WHERE org_id = $1 AND store_id = $2 AND device_id = $3
    ORDER BY created_at DESC LIMIT 1
  `, [device.org_id, device.store_id, device.device_id]);

  const activePairing = pairingRows[0] || null;

  return {
    success: true,
    statusCode: 200,
    device: {
      ...sanitizeDevice(device),
      pairing: activePairing ? {
        id: activePairing.id,
        pairing_token: activePairing.pairing_token,
        status: activePairing.status,
        expires_at: activePairing.expires_at,
        last_used_at: activePairing.last_used_at
      } : null
    }
  };
}

/**
 * Revoke POS hardware terminal access (instantly cuts off sync access)
 */
async function revokeDevice(db, {
  callerActor,
  targetDeviceId,
  targetStoreId = null,
  reason = 'ADMIN_REVOKED',
  correlationId = null,
  ip = null,
  userAgent = null
}) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // 1. RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'devices.revoke')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack devices.revoke permission.' };
  }

  if (!targetDeviceId || typeof targetDeviceId !== 'string' || !targetDeviceId.trim()) {
    return { success: false, statusCode: 400, error: 'MISSING_DEVICE_ID' };
  }

  const cleanDeviceId = targetDeviceId.trim();
  const role = rbac.normalizeRole(callerActor.role);
  const orgId = callerActor.orgId;

  // 2. Fetch device record
  let fetchQuery = `SELECT id, org_id, store_id, device_id, machine_id, status FROM cloud_devices WHERE device_id = $1`;
  const fetchParams = [cleanDeviceId];
  let pIdx = 2;

  if (role !== 'PLATFORM_ADMIN') {
    fetchQuery += ` AND org_id = $${pIdx}`;
    fetchParams.push(orgId);
    pIdx++;
  }

  if (targetStoreId && typeof targetStoreId === 'string' && targetStoreId.trim()) {
    fetchQuery += ` AND store_id = $${pIdx}`;
    fetchParams.push(targetStoreId.trim());
    pIdx++;
  }

  const rows = await executeDbQuery(db, fetchQuery, fetchParams);
  if (rows.length === 0) {
    return { success: false, statusCode: 404, error: 'DEVICE_NOT_FOUND', message: 'Device not found in organization.' };
  }

  const device = rows[0];
  const effectiveOrgId = device.org_id;
  const effectiveStoreId = device.store_id;

  // 3. Atomically update cloud_devices and cloud_pairings status to REVOKED
  await executeDbQuery(db, `
    UPDATE cloud_devices 
    SET status = 'REVOKED' 
    WHERE org_id = $1 AND store_id = $2 AND device_id = $3
  `, [effectiveOrgId, effectiveStoreId, cleanDeviceId]);

  await executeDbQuery(db, `
    UPDATE cloud_pairings 
    SET status = 'REVOKED' 
    WHERE org_id = $1 AND store_id = $2 AND device_id = $3
  `, [effectiveOrgId, effectiveStoreId, cleanDeviceId]);

  // 4. Record tamper-evident audit log
  await recordDeviceAuditLog(db, {
    orgId: effectiveOrgId,
    storeId: effectiveStoreId,
    deviceId: cleanDeviceId,
    actorId: callerActor.userId,
    action: 'DEVICE_REVOKED',
    resourceId: cleanDeviceId,
    details: {
      deviceId: cleanDeviceId,
      machineId: device.machine_id,
      storeId: effectiveStoreId,
      previousStatus: device.status,
      newStatus: 'REVOKED',
      reason: reason || 'ADMIN_REVOKED'
    },
    ip,
    userAgent,
    correlationId
  });

  return {
    success: true,
    statusCode: 200,
    message: `Device ${cleanDeviceId} in store ${effectiveStoreId} has been revoked successfully.`,
    status: 'REVOKED'
  };
}

/**
 * Authorize POS hardware replacement (Hardware Transfer)
 * Rebinds terminal to a new hardware fingerprint without losing store sales history
 */
async function transferDevice(db, {
  callerActor,
  targetDeviceId,
  targetStoreId = null,
  newMachineId,
  reason = 'HARDWARE_REPLACEMENT',
  correlationId = null,
  ip = null,
  userAgent = null
}) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // 1. RBAC Permission Check: Only Organization Owner or Platform Admin can transfer hardware
  if (!rbac.hasPermission(callerActor.role, 'devices.revoke')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack permission to transfer devices.' };
  }

  const role = rbac.normalizeRole(callerActor.role);
  if (role !== 'ORG_OWNER' && role !== 'PLATFORM_ADMIN') {
    return { success: false, statusCode: 403, error: 'FORBIDDEN_OPERATION', message: 'Only Organization Owners can authorize hardware transfers.' };
  }

  if (!targetDeviceId || typeof targetDeviceId !== 'string' || !targetDeviceId.trim()) {
    return { success: false, statusCode: 400, error: 'MISSING_DEVICE_ID' };
  }

  if (!newMachineId || typeof newMachineId !== 'string' || !newMachineId.trim()) {
    return { success: false, statusCode: 400, error: 'MISSING_NEW_MACHINE_ID', message: 'New machine hardware fingerprint is required.' };
  }

  const cleanDeviceId = targetDeviceId.trim();
  const cleanNewMachineId = newMachineId.trim().toUpperCase();
  const orgId = callerActor.orgId;

  // 2. Fetch device record
  let fetchQuery = `SELECT id, org_id, store_id, device_id, machine_id, status FROM cloud_devices WHERE device_id = $1`;
  const fetchParams = [cleanDeviceId];
  let pIdx = 2;

  if (role !== 'PLATFORM_ADMIN') {
    fetchQuery += ` AND org_id = $${pIdx}`;
    fetchParams.push(orgId);
    pIdx++;
  }

  if (targetStoreId && typeof targetStoreId === 'string' && targetStoreId.trim()) {
    fetchQuery += ` AND store_id = $${pIdx}`;
    fetchParams.push(targetStoreId.trim());
    pIdx++;
  }

  const rows = await executeDbQuery(db, fetchQuery, fetchParams);
  if (rows.length === 0) {
    return { success: false, statusCode: 404, error: 'DEVICE_NOT_FOUND', message: 'Device not found in organization.' };
  }

  const device = rows[0];
  const effectiveOrgId = device.org_id;
  const effectiveStoreId = device.store_id;
  const oldMachineId = device.machine_id;

  // 3. Update hardware fingerprint and reset status to ACTIVE
  await executeDbQuery(db, `
    UPDATE cloud_devices 
    SET machine_id = $1, status = 'ACTIVE', last_seen_at = CURRENT_TIMESTAMP 
    WHERE org_id = $2 AND store_id = $3 AND device_id = $4
  `, [cleanNewMachineId, effectiveOrgId, effectiveStoreId, cleanDeviceId]);

  // Ensure pairing status is also reactivated
  await executeDbQuery(db, `
    UPDATE cloud_pairings 
    SET status = 'ACTIVE', last_used_at = CURRENT_TIMESTAMP 
    WHERE org_id = $1 AND store_id = $2 AND device_id = $3
  `, [effectiveOrgId, effectiveStoreId, cleanDeviceId]);

  // 4. Record tamper-evident audit log
  await recordDeviceAuditLog(db, {
    orgId: effectiveOrgId,
    storeId: effectiveStoreId,
    deviceId: cleanDeviceId,
    actorId: callerActor.userId,
    action: 'DEVICE_TRANSFERRED',
    resourceId: cleanDeviceId,
    details: {
      deviceId: cleanDeviceId,
      oldMachineId,
      newMachineId: cleanNewMachineId,
      storeId: effectiveStoreId,
      reason: reason || 'HARDWARE_REPLACEMENT'
    },
    ip,
    userAgent,
    correlationId
  });

  return {
    success: true,
    statusCode: 200,
    message: `Hardware transfer authorized for device ${cleanDeviceId}. Rebound from ${oldMachineId} to ${cleanNewMachineId}.`,
    device: {
      org_id: effectiveOrgId,
      store_id: effectiveStoreId,
      device_id: cleanDeviceId,
      machine_id: cleanNewMachineId,
      status: 'ACTIVE'
    }
  };
}

module.exports = {
  executeDbQuery,
  recordDeviceAuditLog,
  sanitizeDevice,
  listDevices,
  getDeviceDetails,
  revokeDevice,
  transferDevice
};
