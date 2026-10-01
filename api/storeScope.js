/**
 * AMAN CASHIER SAAS — STORE SCOPE & ACCESS ENGINE
 * PHASE 2C-2B / PHASE 2C-2C: Store Scoping, Authorization Resolution, and Access Management
 * 
 * Rules:
 * 1. Client store_id is TARGET ONLY, never an authorization source.
 * 2. Organization ID is strictly derived from Server-Side Authenticated Context (req.auth.orgId).
 * 3. Scoped Roles (STORE_MANAGER, AUDITOR, VIEWER) are strictly bound to cloud_user_store_access.
 * 4. Inactive/Suspended stores are denied operational access.
 * 5. Full Real-Time Revocation on subsequent requests (Authoritative DB check).
 */

const crypto = require('crypto');
const rbac = require('./rbac');

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
    // Replace $1, $2, ... with ? for SQLite compatibility
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
 * Record clean audit log for store access mutation
 */
async function recordStoreAuditLog(db, { orgId, actorId, action, resourceId, details = {}, ip = null, userAgent = null, correlationId = null }) {
  const sanitizedDetails = { ...details };
  // Sanitization: Ensure no sensitive credentials ever enter details JSON
  delete sanitizedDetails.password;
  delete sanitizedDetails.password_hash;
  delete sanitizedDetails.passwordHash;
  delete sanitizedDetails.token;
  delete sanitizedDetails.refreshToken;
  delete sanitizedDetails.deviceKey;

  const query = `
    INSERT INTO cloud_audit_logs 
      (org_id, actor_id, actor_type, action, resource_type, resource_id, correlation_id, details, ip_address, user_agent, created_at)
    VALUES 
      ($1, $2, 'USER', $3, 'STORE_ACCESS', $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
  `;
  try {
    await executeDbQuery(db, query, [
      orgId,
      actorId,
      action,
      resourceId || 'STORE_ACCESS',
      correlationId || `corr_${Date.now()}`,
      JSON.stringify(sanitizedDetails),
      ip,
      userAgent
    ]);
  } catch (err) {
    console.error('[StoreAuditLog Error]:', err.message);
  }
}

/**
 * Retrieve all stores accessible by the authenticated actor based on role and grants
 * @param {Object} db - Database pool / connection
 * @param {Object} authActor - { userId, orgId, role }
 * @returns {Promise<Array<{ store_id, store_name, status, org_id }>>}
 */
async function getUserAccessibleStores(db, authActor) {
  if (!authActor || typeof authActor !== 'object' || !authActor.userId) {
    return [];
  }

  const role = rbac.normalizeRole(authActor.role);
  if (!role) return [];

  const { userId, orgId } = authActor;

  // 1. Platform Admin: Access across platform
  if (role === 'PLATFORM_ADMIN') {
    const query = `
      SELECT org_id, store_id, store_name, status, created_at 
      FROM cloud_stores 
      ORDER BY org_id, created_at ASC
    `;
    return await executeDbQuery(db, query, []);
  }

  // 2. Organization Owner: Global scope across all stores in tenant
  if (role === 'ORG_OWNER') {
    const query = `
      SELECT org_id, store_id, store_name, status, created_at 
      FROM cloud_stores 
      WHERE org_id = $1
      ORDER BY created_at ASC
    `;
    return await executeDbQuery(db, query, [orgId]);
  }

  // 3. Scoped Roles (STORE_MANAGER, AUDITOR, VIEWER): Restricted to cloud_user_store_access
  if (role === 'STORE_MANAGER' || role === 'AUDITOR' || role === 'VIEWER') {
    const query = `
      SELECT cs.org_id, cs.store_id, cs.store_name, cs.status, cs.created_at
      FROM cloud_user_store_access cusa
      JOIN cloud_stores cs 
        ON cusa.org_id = cs.org_id AND cusa.store_id = cs.store_id
      WHERE cusa.user_id = $1 AND cusa.org_id = $2
      ORDER BY cs.created_at ASC
    `;
    return await executeDbQuery(db, query, [userId, orgId]);
  }

  return [];
}

/**
 * Authoritatively validate if the actor has access to a specific target store
 * @param {Object} db - Database pool / connection
 * @param {Object} authActor - { userId, orgId, role }
 * @param {string} targetStoreId - Target store identifier
 * @returns {Promise<{ allowed: boolean, statusCode: number, error?: string, message?: string, store?: object, scope?: string }>}
 */
async function validateStoreAccess(db, authActor, targetStoreId) {
  if (!authActor || typeof authActor !== 'object' || !authActor.userId) {
    return {
      allowed: false,
      statusCode: 401,
      error: 'UNAUTHENTICATED',
      message: 'Authentication context is required.'
    };
  }

  if (!targetStoreId || typeof targetStoreId !== 'string' || targetStoreId.trim() === '') {
    return {
      allowed: false,
      statusCode: 400,
      error: 'INVALID_STORE_ID',
      message: 'Store ID is missing or invalid.'
    };
  }

  const normalizedStoreId = targetStoreId.trim();
  const role = rbac.normalizeRole(authActor.role);
  if (!role) {
    return {
      allowed: false,
      statusCode: 403,
      error: 'INVALID_OR_UNKNOWN_ROLE',
      message: 'Assigned role is unrecognized.'
    };
  }

  const { userId, orgId } = authActor;

  // 1. Platform Admin Scope
  if (role === 'PLATFORM_ADMIN') {
    const query = `SELECT org_id, store_id, store_name, status FROM cloud_stores WHERE store_id = $1`;
    const rows = await executeDbQuery(db, query, [normalizedStoreId]);
    if (rows.length === 0) {
      return { allowed: false, statusCode: 404, error: 'STORE_NOT_FOUND', message: 'Store not found.' };
    }
    const store = rows[0];
    if (store.status === 'SUSPENDED') {
      return { allowed: false, statusCode: 403, error: 'STORE_SUSPENDED', message: 'Store is suspended.' };
    }
    if (store.status === 'DECOMMISSIONED') {
      return { allowed: false, statusCode: 403, error: 'STORE_DECOMMISSIONED', message: 'Store is decommissioned.' };
    }
    return { allowed: true, statusCode: 200, store, scope: 'PLATFORM_SCOPE' };
  }

  // 2. Organization Owner Scope (Global for Tenant)
  if (role === 'ORG_OWNER') {
    const query = `
      SELECT org_id, store_id, store_name, status 
      FROM cloud_stores 
      WHERE org_id = $1 AND store_id = $2
    `;
    const rows = await executeDbQuery(db, query, [orgId, normalizedStoreId]);
    if (rows.length === 0) {
      // Return 404 to prevent object enumeration across tenants
      return { allowed: false, statusCode: 404, error: 'STORE_NOT_FOUND', message: 'Store not found in organization.' };
    }
    const store = rows[0];
    if (store.status === 'SUSPENDED') {
      return { allowed: false, statusCode: 403, error: 'STORE_SUSPENDED', message: 'Store is suspended.' };
    }
    if (store.status === 'DECOMMISSIONED') {
      return { allowed: false, statusCode: 403, error: 'STORE_DECOMMISSIONED', message: 'Store is decommissioned.' };
    }
    return { allowed: true, statusCode: 200, store, scope: 'ORGANIZATION_GLOBAL_SCOPE' };
  }

  // 3. Scoped Roles (STORE_MANAGER, AUDITOR, VIEWER)
  if (role === 'STORE_MANAGER' || role === 'AUDITOR' || role === 'VIEWER') {
    const query = `
      SELECT cs.org_id, cs.store_id, cs.store_name, cs.status
      FROM cloud_user_store_access cusa
      JOIN cloud_stores cs 
        ON cusa.org_id = cs.org_id AND cusa.store_id = cs.store_id
      WHERE cusa.user_id = $1 AND cusa.org_id = $2 AND cusa.store_id = $3
    `;
    const rows = await executeDbQuery(db, query, [userId, orgId, normalizedStoreId]);
    if (rows.length === 0) {
      return {
        allowed: false,
        statusCode: 403,
        error: 'STORE_ACCESS_DENIED',
        message: 'You are not authorized to access this store.'
      };
    }
    const store = rows[0];
    if (store.status === 'SUSPENDED') {
      return { allowed: false, statusCode: 403, error: 'STORE_SUSPENDED', message: 'Store is suspended.' };
    }
    if (store.status === 'DECOMMISSIONED') {
      return { allowed: false, statusCode: 403, error: 'STORE_DECOMMISSIONED', message: 'Store is decommissioned.' };
    }
    return {
      allowed: true,
      statusCode: 200,
      store,
      scope: (role === 'STORE_MANAGER') ? 'STORE_SCOPED' : 'ASSIGNED_STORE_READ_SCOPE'
    };
  }

  return {
    allowed: false,
    statusCode: 403,
    error: 'ROLE_NOT_AUTHORIZED_FOR_STORES',
    message: 'Current role is not authorized for store operations.'
  };
}

/**
 * Express / Connect Middleware Builder for Store Scope Enforcement
 * @param {Object} db - Database connection / pool
 * @param {Object} options - { paramKey: 'storeId', required: false }
 */
function requireStoreScope(db, options = {}) {
  const paramKey = options.paramKey || 'storeId';
  const isRequired = options.required === true;

  return async (req, res, next) => {
    if (!req.auth || !req.auth.userId) {
      return res.status(401).json({
        success: false,
        error: 'UNAUTHENTICATED',
        message: 'Authentication context is required.'
      });
    }

    const targetStoreId = req.params[paramKey] || req.query.store_id || (req.body && req.body.store_id);

    if (!targetStoreId) {
      if (isRequired) {
        return res.status(400).json({
          success: false,
          error: 'MISSING_STORE_ID',
          message: 'Store identifier is required for this operation.'
        });
      }
      return next();
    }

    const validation = await validateStoreAccess(db, req.auth, targetStoreId);
    if (!validation.allowed) {
      return res.status(validation.statusCode).json({
        success: false,
        error: validation.error,
        message: validation.message
      });
    }

    // Attach validated store and authorization context to request object
    req.store = validation.store;
    req.authorizedStoreId = targetStoreId;
    req.storeScope = validation.scope;

    if (typeof next === 'function') next();
  };
}

/**
 * Create a new store under the caller's organization
 */
async function createStore(db, { callerActor, storeName, storeId = null, ip = null, userAgent = null, correlationId = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  if (!rbac.hasPermission(callerActor.role, 'stores.create')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack stores.create permission.' };
  }

  if (!storeName || typeof storeName !== 'string' || !storeName.trim()) {
    return { success: false, statusCode: 400, error: 'STORE_NAME_REQUIRED', message: 'Store name is required.' };
  }

  const orgId = callerActor.orgId;
  const cleanName = storeName.trim();
  const cleanStoreId = (storeId && typeof storeId === 'string' && storeId.trim())
    ? storeId.trim().toUpperCase()
    : `STORE-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;

  const storeToken = 'TOK-' + crypto.randomBytes(16).toString('hex').toUpperCase();

  try {
    const insertQuery = `
      INSERT INTO cloud_stores (org_id, store_id, store_token, store_name, status, created_at, updated_at)
      VALUES ($1, $2, $3, $4, 'ACTIVE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    `;
    await executeDbQuery(db, insertQuery, [orgId, cleanStoreId, storeToken, cleanName]);

    await recordStoreAuditLog(db, {
      orgId,
      actorId: callerActor.userId,
      action: 'STORE_CREATED',
      resourceId: cleanStoreId,
      details: { storeName: cleanName, storeId: cleanStoreId },
      ip,
      userAgent,
      correlationId
    });

    return {
      success: true,
      statusCode: 201,
      message: `Store ${cleanName} created successfully.`,
      store: {
        org_id: orgId,
        store_id: cleanStoreId,
        store_token: storeToken,
        store_name: cleanName,
        status: 'ACTIVE'
      }
    };
  } catch (err) {
    if (err.message.includes('unique_violation') || err.message.includes('UNIQUE constraint failed') || err.message.includes('uq_cloud_stores_org_store')) {
      return { success: false, statusCode: 409, error: 'STORE_ALREADY_EXISTS', message: 'A store with this identifier already exists in your organization.' };
    }
    throw err;
  }
}

/**
 * Retrieve details for a specific store
 */
async function getStoreDetails(db, { callerActor, targetStoreId }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  if (!rbac.hasPermission(callerActor.role, 'stores.read')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack stores.read permission.' };
  }

  const validation = await validateStoreAccess(db, callerActor, targetStoreId);
  if (!validation.allowed) {
    return {
      success: false,
      statusCode: validation.statusCode,
      error: validation.error,
      message: validation.message
    };
  }

  const orgId = validation.store.org_id;
  const storeId = validation.store.store_id;

  const storeQuery = `
    SELECT id, org_id, store_id, store_name, status, created_at, updated_at 
    FROM cloud_stores 
    WHERE org_id = $1 AND store_id = $2
  `;
  const storeRows = await executeDbQuery(db, storeQuery, [orgId, storeId]);
  const storeData = storeRows[0] || validation.store;

  // Retrieve bound devices safely
  let devices = [];
  try {
    const devicesQuery = `
      SELECT device_id, machine_id, status, last_seen_at 
      FROM cloud_devices 
      WHERE org_id = $1 AND store_id = $2
      ORDER BY last_seen_at DESC
    `;
    devices = await executeDbQuery(db, devicesQuery, [orgId, storeId]);
  } catch (e) {
    devices = [];
  }

  return {
    success: true,
    statusCode: 200,
    store: {
      ...storeData,
      devices
    },
    scope: validation.scope
  };
}

/**
 * Update store properties (name, metadata)
 */
async function updateStore(db, { callerActor, targetStoreId, storeName, ip = null, userAgent = null, correlationId = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  if (!rbac.hasPermission(callerActor.role, 'stores.update')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack stores.update permission.' };
  }

  if (!storeName || typeof storeName !== 'string' || !storeName.trim()) {
    return { success: false, statusCode: 400, error: 'STORE_NAME_REQUIRED', message: 'Store name is required.' };
  }

  const validation = await validateStoreAccess(db, callerActor, targetStoreId);
  if (!validation.allowed) {
    return {
      success: false,
      statusCode: validation.statusCode,
      error: validation.error,
      message: validation.message
    };
  }

  const orgId = validation.store.org_id;
  const storeId = validation.store.store_id;
  const cleanName = storeName.trim();

  const updateQuery = `
    UPDATE cloud_stores 
    SET store_name = $1, updated_at = CURRENT_TIMESTAMP 
    WHERE org_id = $2 AND store_id = $3
  `;
  await executeDbQuery(db, updateQuery, [cleanName, orgId, storeId]);

  await recordStoreAuditLog(db, {
    orgId,
    actorId: callerActor.userId,
    action: 'STORE_UPDATED',
    resourceId: storeId,
    details: { oldName: validation.store.store_name, newName: cleanName },
    ip,
    userAgent,
    correlationId
  });

  return {
    success: true,
    statusCode: 200,
    message: `Store ${storeId} successfully updated.`,
    store: {
      org_id: orgId,
      store_id: storeId,
      store_name: cleanName,
      status: validation.store.status
    }
  };
}

/**
 * Change store operational status (ACTIVE, SUSPENDED, DECOMMISSIONED)
 */
async function setStoreStatus(db, { callerActor, targetStoreId, newStatus, ip = null, userAgent = null, correlationId = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  const validStatuses = ['ACTIVE', 'SUSPENDED', 'DECOMMISSIONED'];
  if (!newStatus || !validStatuses.includes(newStatus)) {
    return { success: false, statusCode: 400, error: 'INVALID_STATUS', message: 'Status must be ACTIVE, SUSPENDED, or DECOMMISSIONED.' };
  }

  const requiredPerm = (newStatus === 'ACTIVE') ? 'stores.update' : 'stores.disable';
  if (!rbac.hasPermission(callerActor.role, requiredPerm)) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: `You lack ${requiredPerm} permission.` };
  }

  if (!targetStoreId || typeof targetStoreId !== 'string' || !targetStoreId.trim()) {
    return { success: false, statusCode: 400, error: 'INVALID_STORE_ID', message: 'Store ID is invalid.' };
  }

  const normalizedStoreId = targetStoreId.trim();
  const role = rbac.normalizeRole(callerActor.role);
  const orgId = callerActor.orgId;

  // Check store existence in org (or across platform for PLATFORM_ADMIN)
  let checkQuery = `SELECT org_id, store_id, store_name, status FROM cloud_stores WHERE org_id = $1 AND store_id = $2`;
  let checkParams = [orgId, normalizedStoreId];
  if (role === 'PLATFORM_ADMIN') {
    checkQuery = `SELECT org_id, store_id, store_name, status FROM cloud_stores WHERE store_id = $1`;
    checkParams = [normalizedStoreId];
  }

  const rows = await executeDbQuery(db, checkQuery, checkParams);
  if (rows.length === 0) {
    return { success: false, statusCode: 404, error: 'STORE_NOT_FOUND', message: 'Store not found.' };
  }

  const store = rows[0];
  const targetOrgId = store.org_id;

  const updateQuery = `
    UPDATE cloud_stores 
    SET status = $1, updated_at = CURRENT_TIMESTAMP 
    WHERE org_id = $2 AND store_id = $3
  `;
  await executeDbQuery(db, updateQuery, [newStatus, targetOrgId, normalizedStoreId]);

  let actionName = 'STORE_STATUS_CHANGED';
  if (newStatus === 'SUSPENDED') actionName = 'STORE_SUSPENDED';
  else if (newStatus === 'ACTIVE') actionName = 'STORE_ACTIVATED';
  else if (newStatus === 'DECOMMISSIONED') actionName = 'STORE_DECOMMISSIONED';

  await recordStoreAuditLog(db, {
    orgId: targetOrgId,
    actorId: callerActor.userId,
    action: actionName,
    resourceId: normalizedStoreId,
    details: { oldStatus: store.status, newStatus },
    ip,
    userAgent,
    correlationId
  });

  return {
    success: true,
    statusCode: 200,
    message: `Store ${normalizedStoreId} status updated to ${newStatus}.`,
    status: newStatus
  };
}

/**
 * Retrieve all users granted access to a specific store
 */
async function getStoreUsers(db, { callerActor, targetStoreId }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  if (!rbac.hasPermission(callerActor.role, 'store_access.read')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack store_access.read permission.' };
  }

  const validation = await validateStoreAccess(db, callerActor, targetStoreId);
  if (!validation.allowed) {
    return {
      success: false,
      statusCode: validation.statusCode,
      error: validation.error,
      message: validation.message
    };
  }

  const orgId = validation.store.org_id;
  const storeId = validation.store.store_id;

  const usersQuery = `
    SELECT u.id as user_id, u.email, u.full_name, u.role, u.status as user_status, cusa.created_at as granted_at
    FROM cloud_user_store_access cusa
    JOIN cloud_users u ON cusa.user_id = u.id
    WHERE cusa.org_id = $1 AND cusa.store_id = $2
    ORDER BY cusa.created_at ASC
  `;
  const users = await executeDbQuery(db, usersQuery, [orgId, storeId]);

  return {
    success: true,
    statusCode: 200,
    storeId,
    users
  };
}

/**
 * Grant store access to a specific user within the organization
 */
async function grantStoreAccess(db, { callerActor, targetUserId, targetStoreId, correlationId = null, ip = null, userAgent = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // 1. RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'store_access.grant')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack store_access.grant permission.' };
  }

  if (!targetUserId || !targetStoreId) {
    return { success: false, statusCode: 400, error: 'MISSING_REQUIRED_FIELDS' };
  }

  const orgId = callerActor.orgId;

  // 2. Verify target user belongs to caller's organization
  const userCheck = await executeDbQuery(db, `SELECT id, org_id, role, status FROM cloud_users WHERE id = $1 AND org_id = $2`, [targetUserId, orgId]);
  if (userCheck.length === 0) {
    return { success: false, statusCode: 400, error: 'USER_NOT_IN_ORGANIZATION', message: 'Target user does not belong to your organization.' };
  }

  // 3. Verify target store belongs to caller's organization
  const storeCheck = await executeDbQuery(db, `SELECT store_id, org_id, status FROM cloud_stores WHERE store_id = $1 AND org_id = $2`, [targetStoreId, orgId]);
  if (storeCheck.length === 0) {
    return { success: false, statusCode: 400, error: 'STORE_NOT_IN_ORGANIZATION', message: 'Target store does not belong to your organization.' };
  }

  // 4. Insert into cloud_user_store_access
  try {
    const insertQuery = `
      INSERT INTO cloud_user_store_access (org_id, user_id, store_id, created_at)
      VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
    `;
    await executeDbQuery(db, insertQuery, [orgId, targetUserId, targetStoreId]);

    // 5. Record clean audit log
    await recordStoreAuditLog(db, {
      orgId,
      actorId: callerActor.userId,
      action: 'STORE_ACCESS_GRANTED',
      resourceId: targetStoreId,
      details: { targetUserId, targetStoreId },
      ip,
      userAgent,
      correlationId
    });

    return {
      success: true,
      statusCode: 200,
      message: `Access to store ${targetStoreId} successfully granted to user ${targetUserId}.`
    };
  } catch (err) {
    if (err.message.includes('unique_violation') || err.message.includes('UNIQUE constraint failed') || err.message.includes('uq_user_store_access')) {
      return { success: false, statusCode: 409, error: 'STORE_ACCESS_ALREADY_GRANTED', message: 'Store access is already granted for this user.' };
    }
    if (err.message.includes('foreign_key_violation') || err.message.includes('FOREIGN KEY constraint failed')) {
      return { success: false, statusCode: 400, error: 'CROSS_ORG_STORE_REJECTED', message: 'Store does not belong to the user organization.' };
    }
    throw err;
  }
}

/**
 * Revoke store access from a specific user within the organization
 */
async function revokeStoreAccess(db, { callerActor, targetUserId, targetStoreId, correlationId = null, ip = null, userAgent = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // 1. RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'store_access.revoke')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack store_access.revoke permission.' };
  }

  if (!targetUserId || !targetStoreId) {
    return { success: false, statusCode: 400, error: 'MISSING_REQUIRED_FIELDS' };
  }

  const orgId = callerActor.orgId;

  const deleteQuery = `
    DELETE FROM cloud_user_store_access 
    WHERE org_id = $1 AND user_id = $2 AND store_id = $3
  `;
  await executeDbQuery(db, deleteQuery, [orgId, targetUserId, targetStoreId]);

  // Record clean audit log
  await recordStoreAuditLog(db, {
    orgId,
    actorId: callerActor.userId,
    action: 'STORE_ACCESS_REVOKED',
    resourceId: targetStoreId,
    details: { targetUserId, targetStoreId },
    ip,
    userAgent,
    correlationId
  });

  return {
    success: true,
    statusCode: 200,
    message: `Access to store ${targetStoreId} revoked from user ${targetUserId}.`
  };
}

module.exports = {
  executeDbQuery,
  recordStoreAuditLog,
  getUserAccessibleStores,
  validateStoreAccess,
  requireStoreScope,
  createStore,
  getStoreDetails,
  updateStore,
  setStoreStatus,
  getStoreUsers,
  grantStoreAccess,
  revokeStoreAccess
};
