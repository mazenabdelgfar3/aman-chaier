/**
 * AMAN CASHIER SAAS — USER MANAGEMENT & ORGANIZATION SETTINGS ENGINE
 * PHASE 2C-2D: Cloud User Lifecycle, Organization Settings, and Access Management
 * 
 * Rules:
 * 1. Authority strictly derived from Server-Side Authenticated Context (req.auth.org_id, req.auth.role, req.auth.user_id).
 * 2. Client org_id / role / user_id are TARGET ONLY or completely ignored for authorization.
 * 3. Non-executable ORG_ADMIN cannot be created or assigned.
 * 4. Last ORG_OWNER protection prevents deactivating or demoting the single active owner.
 * 5. Real-time session invalidation when deactivating a user.
 * 6. Cross-tenant user access / store assignment strictly prohibited.
 * 7. Passwords and hashes strictly sanitized from all API responses and audit logs.
 */

const crypto = require('crypto');
const rbac = require('./rbac');
const auth = require('./auth');

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
 * Record clean audit log for user/org management mutation
 */
async function recordUserOrgAuditLog(db, { orgId, actorId, action, resourceType, resourceId, details = {}, ip = null, userAgent = null, correlationId = null }) {
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
      ($1, $2, 'USER', $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
  `;
  try {
    await executeDbQuery(db, query, [
      orgId,
      actorId,
      action,
      resourceType || 'USER',
      resourceId || 'MANAGEMENT',
      correlationId || `corr_${Date.now()}`,
      JSON.stringify(sanitizedDetails),
      ip,
      userAgent
    ]);
  } catch (err) {
    console.error('[UserOrgAuditLog Error]:', err.message);
  }
}

/**
 * Sanitize user object to never leak password_hash
 */
function sanitizeUser(user) {
  if (!user) return null;
  const copy = { ...user };
  delete copy.password_hash;
  delete copy.password;
  return copy;
}

/**
 * List all users in caller's organization
 */
async function listUsers(db, { callerActor, roleFilter = null, statusFilter = null, search = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'users.read')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack users.read permission.' };
  }

  const orgId = callerActor.orgId;
  let query = `
    SELECT id, org_id, email, username, full_name, role, status, 
           failed_login_attempts, locked_until, last_login_at, created_at, updated_at
    FROM cloud_users 
    WHERE org_id = $1
  `;
  const params = [orgId];
  let paramIndex = 2;

  if (roleFilter) {
    const normRole = rbac.normalizeRole(roleFilter);
    if (normRole) {
      query += ` AND role = $${paramIndex++}`;
      params.push(normRole);
    }
  }

  if (statusFilter) {
    const normStatus = statusFilter.trim().toUpperCase();
    if (['ACTIVE', 'SUSPENDED', 'LOCKED', 'DEACTIVATED'].includes(normStatus)) {
      query += ` AND status = $${paramIndex++}`;
      params.push(normStatus);
    }
  }

  if (search && typeof search === 'string' && search.trim().length > 0) {
    const sTerm = `%${search.trim().toLowerCase()}%`;
    query += ` AND (LOWER(email) LIKE $${paramIndex} OR LOWER(full_name) LIKE $${paramIndex + 1})`;
    params.push(sTerm, sTerm);
    paramIndex += 2;
  }

  query += ` ORDER BY created_at ASC`;

  const users = await executeDbQuery(db, query, params);
  return {
    success: true,
    statusCode: 200,
    users: users.map(sanitizeUser)
  };
}

/**
 * Create a new user in caller's organization
 */
async function createUser(db, { callerActor, email, password, fullName, role, status = 'ACTIVE', correlationId = null, ip = null, userAgent = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'users.create')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack users.create permission.' };
  }

  if (!email || !password || !fullName || !role) {
    return { success: false, statusCode: 400, error: 'MISSING_REQUIRED_FIELDS', message: 'Email, password, fullName, and role are required.' };
  }

  const normalizedEmail = email.trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(normalizedEmail)) {
    return { success: false, statusCode: 400, error: 'INVALID_EMAIL_FORMAT', message: 'Invalid email address format.' };
  }

  if (typeof password !== 'string' || password.length < 6) {
    return { success: false, statusCode: 400, error: 'WEAK_PASSWORD', message: 'Password must be at least 6 characters.' };
  }

  // Security Rule: ORG_ADMIN is NON-EXECUTABLE
  if (role.trim().toUpperCase() === 'ORG_ADMIN') {
    return { success: false, statusCode: 400, error: 'NON_EXECUTABLE_ROLE', message: 'ORG_ADMIN role is non-executable and cannot be assigned.' };
  }

  const normalizedRole = rbac.normalizeRole(role);
  if (!normalizedRole) {
    return { success: false, statusCode: 400, error: 'INVALID_ROLE', message: 'Specified role is not recognized.' };
  }

  // Security Rule: Non-Platform Admins cannot create PLATFORM_ADMIN
  if (normalizedRole === 'PLATFORM_ADMIN' && callerActor.role !== 'PLATFORM_ADMIN') {
    return { success: false, statusCode: 403, error: 'FORBIDDEN_ROLE_CREATION', message: 'Only Platform Admins can create Platform Admin accounts.' };
  }

  const normalizedStatus = (status || 'ACTIVE').trim().toUpperCase();
  if (!['ACTIVE', 'SUSPENDED', 'LOCKED', 'DEACTIVATED'].includes(normalizedStatus)) {
    return { success: false, statusCode: 400, error: 'INVALID_STATUS', message: 'Invalid user status.' };
  }

  const orgId = callerActor.orgId;

  // Check for email collision in caller's organization
  const existing = await executeDbQuery(db, `SELECT id FROM cloud_users WHERE org_id = $1 AND LOWER(email) = $2`, [orgId, normalizedEmail]);
  if (existing.length > 0) {
    return { success: false, statusCode: 409, error: 'EMAIL_ALREADY_EXISTS', message: 'A user with this email already exists in the organization.' };
  }

  const passwordHash = auth.hashPassword(password);
  const newUserId = crypto.randomUUID ? crypto.randomUUID() : 'usr_' + crypto.randomBytes(16).toString('hex');

  const insertQuery = `
    INSERT INTO cloud_users 
      (id, org_id, email, username, password_hash, full_name, role, status, created_at, updated_at)
    VALUES 
      ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
  `;

  await executeDbQuery(db, insertQuery, [
    newUserId,
    orgId,
    normalizedEmail,
    normalizedEmail.split('@')[0],
    passwordHash,
    fullName.trim(),
    normalizedRole,
    normalizedStatus
  ]);

  // Record audit log
  await recordUserOrgAuditLog(db, {
    orgId,
    actorId: callerActor.userId,
    action: 'USER_CREATED',
    resourceType: 'USER',
    resourceId: newUserId,
    details: { targetUserId: newUserId, email: normalizedEmail, role: normalizedRole, status: normalizedStatus },
    ip,
    userAgent,
    correlationId
  });

  return {
    success: true,
    statusCode: 201,
    user: {
      id: newUserId,
      org_id: orgId,
      email: normalizedEmail,
      full_name: fullName.trim(),
      role: normalizedRole,
      status: normalizedStatus
    }
  };
}

/**
 * Get user profile and assigned stores
 */
async function getUserDetails(db, { callerActor, targetUserId }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'users.read')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack users.read permission.' };
  }

  if (!targetUserId) {
    return { success: false, statusCode: 400, error: 'MISSING_USER_ID' };
  }

  const orgId = callerActor.orgId;
  const userRows = await executeDbQuery(db, `
    SELECT id, org_id, email, username, full_name, role, status, 
           failed_login_attempts, locked_until, last_login_at, created_at, updated_at
    FROM cloud_users 
    WHERE id = $1 AND org_id = $2
  `, [targetUserId, orgId]);

  if (userRows.length === 0) {
    return { success: false, statusCode: 404, error: 'USER_NOT_FOUND', message: 'User not found in organization.' };
  }

  const user = sanitizeUser(userRows[0]);

  // Retrieve assigned stores
  const storeRows = await executeDbQuery(db, `
    SELECT s.store_id, s.store_name, s.status, a.created_at as assigned_at
    FROM cloud_user_store_access a
    JOIN cloud_stores s ON a.org_id = s.org_id AND a.store_id = s.store_id
    WHERE a.user_id = $1 AND a.org_id = $2
    ORDER BY s.store_name ASC
  `, [targetUserId, orgId]);

  return {
    success: true,
    statusCode: 200,
    user: {
      ...user,
      assigned_stores: storeRows
    }
  };
}

const tenantLocks = new Map();

/**
 * Serializes concurrent operations per organization within the process
 */
async function withTenantLock(orgId, callback) {
  if (!orgId) return await callback();
  while (tenantLocks.has(orgId)) {
    try {
      await tenantLocks.get(orgId);
    } catch {}
  }
  let resolveLock;
  const lockPromise = new Promise((resolve) => { resolveLock = resolve; });
  tenantLocks.set(orgId, lockPromise);

  try {
    return await callback();
  } finally {
    tenantLocks.delete(orgId);
    resolveLock();
  }
}

/**
 * Executes a callback within a strict ACID transaction supporting both PostgreSQL and SQLite
 */
async function withDbTransaction(db, callback) {
  if (typeof db.connect === 'function') {
    // db is a PostgreSQL Pool
    const client = await db.connect();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try { await client.query('ROLLBACK'); } catch {}
      throw err;
    } finally {
      client.release();
    }
  } else if (typeof db.query === 'function') {
    // db is already a PostgreSQL client / connection in an active transaction
    return await callback(db);
  } else if (typeof db.prepare === 'function') {
    // Better-SQLite3 database
    if (db.inTransaction) {
      return await callback(db);
    }
    try {
      db.prepare('BEGIN IMMEDIATE').run();
      const result = await callback(db);
      db.prepare('COMMIT').run();
      return result;
    } catch (err) {
      try { db.prepare('ROLLBACK').run(); } catch {}
      throw err;
    }
  }
  return await callback(db);
}

/**
 * Update user details (full_name, role) with atomic Last-Owner protection
 */
async function updateUser(db, { callerActor, targetUserId, fullName, role, correlationId = null, ip = null, userAgent = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'users.update')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack users.update permission.' };
  }

  if (!targetUserId) {
    return { success: false, statusCode: 400, error: 'MISSING_USER_ID' };
  }

  const orgId = callerActor.orgId;

  return await withTenantLock(orgId, async () => {
    return await withDbTransaction(db, async (txDb) => {
      // In PostgreSQL: Serialize concurrent owner modifications across processes using row-level locking
      if (typeof txDb.query === 'function') {
        await txDb.query(`SELECT id FROM cloud_organizations WHERE org_id = $1 FOR UPDATE`, [orgId]);
      }

      const userRows = await executeDbQuery(txDb, `SELECT id, org_id, email, role, status FROM cloud_users WHERE id = $1 AND org_id = $2`, [targetUserId, orgId]);
      if (userRows.length === 0) {
        return { success: false, statusCode: 404, error: 'USER_NOT_FOUND', message: 'User not found in organization.' };
      }

      const existingUser = userRows[0];
      let updatedFullName = existingUser.full_name;
      let updatedRole = existingUser.role;

      if (fullName && typeof fullName === 'string' && fullName.trim().length > 0) {
        updatedFullName = fullName.trim();
      }

      if (role) {
        if (role.trim().toUpperCase() === 'ORG_ADMIN') {
          return { success: false, statusCode: 400, error: 'NON_EXECUTABLE_ROLE', message: 'ORG_ADMIN is non-executable.' };
        }
        const normRole = rbac.normalizeRole(role);
        if (!normRole) {
          return { success: false, statusCode: 400, error: 'INVALID_ROLE', message: 'Specified role is invalid.' };
        }
        if (normRole === 'PLATFORM_ADMIN' && callerActor.role !== 'PLATFORM_ADMIN') {
          return { success: false, statusCode: 403, error: 'FORBIDDEN_ROLE_ESCALATION', message: 'Cannot promote user to Platform Admin.' };
        }

        // Last Owner Protection: If demoting an ORG_OWNER to another role, check active owner count
        if (existingUser.role === 'ORG_OWNER' && normRole !== 'ORG_OWNER') {
          const activeOwners = await executeDbQuery(txDb, `
            SELECT COUNT(*) as count FROM cloud_users 
            WHERE org_id = $1 AND role = 'ORG_OWNER' AND status = 'ACTIVE'
          `, [orgId]);
          const ownerCount = parseInt(activeOwners[0].count || activeOwners[0].COUNT || 0, 10);
          if (ownerCount <= 1) {
            return { 
              success: false, 
              statusCode: 400, 
              error: 'LAST_OWNER_PROTECTION', 
              message: 'Cannot change the role of the last active organization owner.' 
            };
          }
        }
        updatedRole = normRole;
      }

      const updateQuery = `
        UPDATE cloud_users 
        SET full_name = COALESCE($1, full_name),
            role = COALESCE($2, role),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $3 AND org_id = $4
      `;

      await executeDbQuery(txDb, updateQuery, [updatedFullName, updatedRole, targetUserId, orgId]);

      // Record audit log
      await recordUserOrgAuditLog(txDb, {
        orgId,
        actorId: callerActor.userId,
        action: 'USER_UPDATED',
        resourceType: 'USER',
        resourceId: targetUserId,
        details: { targetUserId, updatedFullName, updatedRole },
        ip,
        userAgent,
        correlationId
      });

      return {
        success: true,
        statusCode: 200,
        message: 'User details updated successfully.'
      };
    });
  });
}

/**
 * Set user status (ACTIVE, SUSPENDED, DEACTIVATED) with Last-Owner protection and Session Invalidation
 */
async function setUserStatus(db, { callerActor, targetUserId, newStatus, correlationId = null, ip = null, userAgent = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  const normalizedStatus = (newStatus || '').trim().toUpperCase();
  if (!['ACTIVE', 'SUSPENDED', 'DEACTIVATED'].includes(normalizedStatus)) {
    return { success: false, statusCode: 400, error: 'INVALID_STATUS', message: 'Status must be ACTIVE, SUSPENDED, or DEACTIVATED.' };
  }

  // RBAC Permission Check
  const requiredPerm = normalizedStatus === 'ACTIVE' ? 'users.update' : 'users.disable';
  if (!rbac.hasPermission(callerActor.role, requiredPerm)) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: `You lack ${requiredPerm} permission.` };
  }

  if (!targetUserId) {
    return { success: false, statusCode: 400, error: 'MISSING_USER_ID' };
  }

  const orgId = callerActor.orgId;

  return await withTenantLock(orgId, async () => {
    return await withDbTransaction(db, async (txDb) => {
      // In PostgreSQL: Serialize concurrent owner modifications using row-level locking
      if (typeof txDb.query === 'function') {
        await txDb.query(`SELECT id FROM cloud_organizations WHERE org_id = $1 FOR UPDATE`, [orgId]);
      }

      const userRows = await executeDbQuery(txDb, `SELECT id, org_id, email, role, status FROM cloud_users WHERE id = $1 AND org_id = $2`, [targetUserId, orgId]);
      if (userRows.length === 0) {
        return { success: false, statusCode: 404, error: 'USER_NOT_FOUND', message: 'User not found in organization.' };
      }

      const targetUser = userRows[0];

      // Last Owner Protection: If deactivating/suspending an ORG_OWNER
      if (targetUser.role === 'ORG_OWNER' && targetUser.status === 'ACTIVE' && normalizedStatus !== 'ACTIVE') {
        const activeOwners = await executeDbQuery(txDb, `
          SELECT COUNT(*) as count FROM cloud_users 
          WHERE org_id = $1 AND role = 'ORG_OWNER' AND status = 'ACTIVE'
        `, [orgId]);
        const ownerCount = parseInt(activeOwners[0].count || activeOwners[0].COUNT || 0, 10);
        if (ownerCount <= 1) {
          return { 
            success: false, 
            statusCode: 400, 
            error: 'LAST_OWNER_PROTECTION', 
            message: 'Cannot deactivate or suspend the last active organization owner.' 
          };
        }
      }

      // Update user status
      await executeDbQuery(txDb, `
        UPDATE cloud_users 
        SET status = $1, updated_at = CURRENT_TIMESTAMP 
        WHERE id = $2 AND org_id = $3
      `, [normalizedStatus, targetUserId, orgId]);

      // Real-Time Session Invalidation: If deactivating or suspending, revoke all active sessions
      if (normalizedStatus === 'DEACTIVATED' || normalizedStatus === 'SUSPENDED') {
        const revokeReason = normalizedStatus === 'DEACTIVATED' ? 'USER_DEACTIVATED' : 'USER_SUSPENDED';
        await executeDbQuery(txDb, `
          UPDATE cloud_user_sessions 
          SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = $1 
          WHERE user_id = $2 AND org_id = $3 AND revoked_at IS NULL
        `, [revokeReason, targetUserId, orgId]);
      }

      // Record audit log
      const auditAction = normalizedStatus === 'ACTIVE' ? 'USER_ACTIVATED' : (normalizedStatus === 'DEACTIVATED' ? 'USER_DEACTIVATED' : 'USER_SUSPENDED');
      await recordUserOrgAuditLog(txDb, {
        orgId,
        actorId: callerActor.userId,
        action: auditAction,
        resourceType: 'USER',
        resourceId: targetUserId,
        details: { targetUserId, previousStatus: targetUser.status, newStatus: normalizedStatus },
        ip,
        userAgent,
        correlationId
      });

      return {
        success: true,
        statusCode: 200,
        message: `User status set to ${normalizedStatus}.`
      };
    });
  });
}

/**
 * Get assigned stores for a specific user
 */
async function getUserAssignedStores(db, { callerActor, targetUserId }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'store_access.read') && !rbac.hasPermission(callerActor.role, 'users.read')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack permission to view store assignments.' };
  }

  if (!targetUserId) {
    return { success: false, statusCode: 400, error: 'MISSING_USER_ID' };
  }

  const orgId = callerActor.orgId;
  const userCheck = await executeDbQuery(db, `SELECT id FROM cloud_users WHERE id = $1 AND org_id = $2`, [targetUserId, orgId]);
  if (userCheck.length === 0) {
    return { success: false, statusCode: 404, error: 'USER_NOT_FOUND', message: 'User not found in organization.' };
  }

  const storeRows = await executeDbQuery(db, `
    SELECT s.store_id, s.store_name, s.status, a.created_at as assigned_at
    FROM cloud_user_store_access a
    JOIN cloud_stores s ON a.org_id = s.org_id AND a.store_id = s.store_id
    WHERE a.user_id = $1 AND a.org_id = $2
    ORDER BY s.store_name ASC
  `, [targetUserId, orgId]);

  return {
    success: true,
    statusCode: 200,
    stores: storeRows
  };
}

/**
 * Assign store access to user
 */
async function assignUserStore(db, { callerActor, targetUserId, targetStoreId, correlationId = null, ip = null, userAgent = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'store_access.grant')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack store_access.grant permission.' };
  }

  if (!targetUserId || !targetStoreId) {
    return { success: false, statusCode: 400, error: 'MISSING_REQUIRED_FIELDS' };
  }

  const orgId = callerActor.orgId;

  // Verify target user belongs to caller's org
  const userCheck = await executeDbQuery(db, `SELECT id FROM cloud_users WHERE id = $1 AND org_id = $2`, [targetUserId, orgId]);
  if (userCheck.length === 0) {
    return { success: false, statusCode: 404, error: 'USER_NOT_FOUND', message: 'User not found in organization.' };
  }

  // Verify target store belongs to caller's org
  const storeCheck = await executeDbQuery(db, `SELECT store_id FROM cloud_stores WHERE store_id = $1 AND org_id = $2`, [targetStoreId, orgId]);
  if (storeCheck.length === 0) {
    return { success: false, statusCode: 404, error: 'STORE_NOT_FOUND', message: 'Store not found in organization.' };
  }

  try {
    const insertQuery = `
      INSERT INTO cloud_user_store_access (org_id, user_id, store_id, created_at)
      VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
    `;
    await executeDbQuery(db, insertQuery, [orgId, targetUserId, targetStoreId]);

    // Record audit log
    await recordUserOrgAuditLog(db, {
      orgId,
      actorId: callerActor.userId,
      action: 'STORE_ACCESS_GRANTED',
      resourceType: 'STORE_ACCESS',
      resourceId: targetStoreId,
      details: { targetUserId, targetStoreId },
      ip,
      userAgent,
      correlationId
    });

    return {
      success: true,
      statusCode: 200,
      message: `Store ${targetStoreId} assigned to user ${targetUserId} successfully.`
    };
  } catch (err) {
    if (err.message.includes('unique_violation') || err.message.includes('UNIQUE constraint failed') || err.message.includes('uq_user_store_access')) {
      return { success: false, statusCode: 409, error: 'STORE_ALREADY_ASSIGNED', message: 'User already has access to this store.' };
    }
    throw err;
  }
}

/**
 * Unassign store access from user
 */
async function unassignUserStore(db, { callerActor, targetUserId, targetStoreId, correlationId = null, ip = null, userAgent = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // RBAC Permission Check
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

  // Record audit log
  await recordUserOrgAuditLog(db, {
    orgId,
    actorId: callerActor.userId,
    action: 'STORE_ACCESS_REVOKED',
    resourceType: 'STORE_ACCESS',
    resourceId: targetStoreId,
    details: { targetUserId, targetStoreId },
    ip,
    userAgent,
    correlationId
  });

  return {
    success: true,
    statusCode: 200,
    message: `Store ${targetStoreId} unassigned from user ${targetUserId} successfully.`
  };
}

/**
 * Get caller's organization details and settings
 */
async function getOrganizationDetails(db, { callerActor }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'org.read')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack org.read permission.' };
  }

  const orgId = callerActor.orgId;
  const orgRows = await executeDbQuery(db, `
    SELECT id, org_id, org_name, status, created_at, updated_at 
    FROM cloud_organizations 
    WHERE org_id = $1
  `, [orgId]);

  if (orgRows.length === 0) {
    return { success: false, statusCode: 404, error: 'ORGANIZATION_NOT_FOUND', message: 'Organization record not found.' };
  }

  // Get aggregated stats for dashboard view
  const userCountRows = await executeDbQuery(db, `SELECT COUNT(*) as total_users FROM cloud_users WHERE org_id = $1`, [orgId]);
  const storeCountRows = await executeDbQuery(db, `SELECT COUNT(*) as total_stores FROM cloud_stores WHERE org_id = $1`, [orgId]);

  return {
    success: true,
    statusCode: 200,
    organization: {
      ...orgRows[0],
      stats: {
        total_users: parseInt(userCountRows[0].total_users || userCountRows[0].TOTAL_USERS || 0, 10),
        total_stores: parseInt(storeCountRows[0].total_stores || storeCountRows[0].TOTAL_STORES || 0, 10)
      }
    }
  };
}

/**
 * Update caller's organization details (e.g. org_name)
 */
async function updateOrganizationDetails(db, { callerActor, orgName, correlationId = null, ip = null, userAgent = null }) {
  if (!callerActor || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED' };
  }

  // RBAC Permission Check
  if (!rbac.hasPermission(callerActor.role, 'org.update')) {
    return { success: false, statusCode: 403, error: 'PERMISSION_DENIED', message: 'You lack org.update permission.' };
  }

  if (!orgName || typeof orgName !== 'string' || orgName.trim().length === 0) {
    return { success: false, statusCode: 400, error: 'INVALID_ORG_NAME', message: 'Organization name cannot be empty.' };
  }

  const orgId = callerActor.orgId;
  const cleanOrgName = orgName.trim();

  await executeDbQuery(db, `
    UPDATE cloud_organizations 
    SET org_name = $1, updated_at = CURRENT_TIMESTAMP 
    WHERE org_id = $2
  `, [cleanOrgName, orgId]);

  // Record audit log
  await recordUserOrgAuditLog(db, {
    orgId,
    actorId: callerActor.userId,
    action: 'ORG_UPDATED',
    resourceType: 'ORGANIZATION',
    resourceId: orgId,
    details: { orgName: cleanOrgName },
    ip,
    userAgent,
    correlationId
  });

  return {
    success: true,
    statusCode: 200,
    message: 'Organization details updated successfully.',
    organization: {
      org_id: orgId,
      org_name: cleanOrgName
    }
  };
}

module.exports = {
  executeDbQuery,
  recordUserOrgAuditLog,
  sanitizeUser,
  listUsers,
  createUser,
  getUserDetails,
  updateUser,
  setUserStatus,
  getUserAssignedStores,
  assignUserStore,
  unassignUserStore,
  getOrganizationDetails,
  updateOrganizationDetails
};
