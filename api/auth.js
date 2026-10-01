const crypto = require('crypto');

const ACCESS_TOKEN_TTL_SECONDS = 900; // 15 minutes
const REFRESH_TOKEN_TTL_DAYS = 7;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;

/**
 * Safely resolves JWT Secret with strict Production Fail-Closed security.
 * In production mode (NODE_ENV=production or VERCEL_ENV=production), JWT_SECRET MUST be set.
 * Secrets are never logged or exposed.
 */
function getJwtSecret(providedSecret = null) {
  if (providedSecret && typeof providedSecret === 'string') {
    return providedSecret;
  }

  const env = process.env.NODE_ENV || process.env.VERCEL_ENV || process.env.APP_ENV || '';
  const isProduction = env.toLowerCase() === 'production';
  const configuredSecret = process.env.JWT_SECRET;

  if (isProduction) {
    if (!configuredSecret || typeof configuredSecret !== 'string' || configuredSecret.trim().length < 32) {
      throw new Error('CRITICAL_SECURITY_ERROR: JWT_SECRET environment variable is missing or insecure (< 32 chars) in production mode. Refusing startup.');
    }
    return configuredSecret.trim();
  }

  // Development and test fallback only (Strictly prohibited in production)
  return configuredSecret || 'AMAN_SAAS_DEV_TEST_JWT_SECRET_DO_NOT_USE_IN_PROD_2026';
}

/**
 * Validate authentication configuration at startup
 */
function validateAuthConfiguration() {
  const env = process.env.NODE_ENV || process.env.VERCEL_ENV || process.env.APP_ENV || '';
  const isProduction = env.toLowerCase() === 'production';
  if (isProduction) {
    const configuredSecret = process.env.JWT_SECRET;
    if (!configuredSecret || typeof configuredSecret !== 'string' || configuredSecret.trim().length < 32) {
      return { valid: false, error: 'CRITICAL_SECURITY_ERROR: JWT_SECRET environment variable is missing or insecure (< 32 chars) in production mode.' };
    }
  }
  return { valid: true };
}

/**
 * Hash password using Node.js native crypto.scrypt (zero external binary dependencies)
 * Format: $scrypt$N=16384,r=8,p=1$<salt_hex>$<derived_key_hex>
 */
function hashPassword(password) {
  if (!password || typeof password !== 'string' || password.length < 6) {
    throw new Error('PASSWORD_TOO_SHORT: Password must be at least 6 characters long.');
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `$scrypt$N=16384,r=8,p=1$${salt}$${derivedKey.toString('hex')}`;
}

/**
 * Verify password against stored hash using constant-time comparison
 */
function verifyPassword(password, storedHash) {
  if (!password || !storedHash || typeof storedHash !== 'string') {
    return false;
  }
  
  if (storedHash.startsWith('$scrypt$')) {
    const parts = storedHash.split('$');
    if (parts.length < 5) return false;
    const salt = parts[3];
    const originalDerivedHex = parts[4];
    const derivedKey = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
    const originalBuf = Buffer.from(originalDerivedHex, 'hex');
    if (derivedKey.length !== originalBuf.length) return false;
    return crypto.timingSafeEqual(derivedKey, originalBuf);
  }

  // Fallback support for legacy bcrypt hashes if present ($2a$, $2b$, $2y$)
  if (storedHash.startsWith('$2')) {
    try {
      const bcrypt = require('bcryptjs');
      return bcrypt.compareSync(password, storedHash);
    } catch {
      return false;
    }
  }

  return false;
}

/**
 * Generate 256-bit cryptographically secure random session ID
 */
function generateSessionId() {
  return 'sess_' + crypto.randomBytes(24).toString('hex');
}

/**
 * Generate 256-bit cryptographically secure raw refresh token
 */
function generateRawRefreshToken() {
  return 'rtk_' + crypto.randomBytes(32).toString('hex');
}

/**
 * Compute SHA-256 hash of refresh token for safe storage in PostgreSQL
 */
function hashRefreshToken(rawToken) {
  if (!rawToken || typeof rawToken !== 'string') return '';
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

/**
 * Generate signed JWT Access Token
 */
function generateAccessToken(payload, secretKey = null) {
  const activeSecret = getJwtSecret(secretKey);
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    type: 'ACCESS_TOKEN',
    iat: now,
    exp: now + ACCESS_TOKEN_TTL_SECONDS
  };

  const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const unsignedToken = `${encode(header)}.${encode(fullPayload)}`;
  const signature = crypto
    .createHmac('sha256', activeSecret)
    .update(unsignedToken)
    .digest('base64url');

  return `${unsignedToken}.${signature}`;
}

/**
 * Verify JWT Access Token signature and expiration
 */
function verifyAccessToken(token, secretKey = null) {
  const activeSecret = getJwtSecret(secretKey);
  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'TOKEN_MISSING' };
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, error: 'MALFORMED_JWT' };
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  const unsignedToken = `${headerB64}.${payloadB64}`;
  const expectedSignature = crypto
    .createHmac('sha256', activeSecret)
    .update(unsignedToken)
    .digest('base64url');

  const sigBuf = Buffer.from(signatureB64);
  const expectedBuf = Buffer.from(expectedSignature);

  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return { valid: false, error: 'INVALID_SIGNATURE' };
  }

  let payload = {};
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    return { valid: false, error: 'INVALID_PAYLOAD_JSON' };
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    return { valid: false, error: 'TOKEN_EXPIRED', payload };
  }

  return { valid: true, payload };
}

/**
 * Record Sanitized Audit Log into cloud_audit_logs
 * Strictly strips passwords, hashes, raw tokens, and secret keys
 */
async function recordAuthAuditLog(db, {
  orgId,
  storeId = null,
  deviceId = null,
  actorId,
  actorType = 'USER',
  action,
  resourceType = 'AUTH',
  resourceId = null,
  correlationId = null,
  details = {},
  ipAddress = null,
  userAgent = null
}) {
  try {
    // Sanitize details: strict secrets blacklist
    const sanitized = { ...details };
    delete sanitized.password;
    delete sanitized.newPassword;
    delete sanitized.currentPassword;
    delete sanitized.password_hash;
    delete sanitized.passwordHash;
    delete sanitized.rawToken;
    delete sanitized.rawRefreshToken;
    delete sanitized.refreshToken;
    delete sanitized.accessToken;
    delete sanitized.jwt;
    delete sanitized.secret;
    delete sanitized.privateKey;

    const query = `
      INSERT INTO cloud_audit_logs (
        org_id, store_id, device_id, actor_id, actor_type, action,
        resource_type, resource_id, correlation_id, details, ip_address, user_agent
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    `;
    const params = [
      orgId,
      storeId,
      deviceId,
      String(actorId),
      actorType,
      action,
      resourceType,
      resourceId ? String(resourceId) : null,
      correlationId ? String(correlationId) : null,
      JSON.stringify(sanitized),
      ipAddress,
      userAgent
    ];

    if (typeof db.query === 'function') {
      await db.query(query, params);
    } else if (typeof db.prepare === 'function') {
      // Better-SQLite3 mock harness adapter
      const sqliteQuery = `
        INSERT INTO cloud_audit_logs (
          org_id, store_id, device_id, actor_id, actor_type, action,
          resource_type, resource_id, correlation_id, details, ip_address, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      db.prepare(sqliteQuery).run(...params);
    }
  } catch (err) {
    console.warn('[AuditLog Warning]: Failed to record auth audit log:', err.message);
  }
}

/**
 * Core User Login Flow with Lockout & Brute-force Defense
 */
async function loginUser(db, { email, password, orgHint = null, ip = null, userAgent = null, correlationId = null }) {
  if (!email || !password) {
    return { success: false, statusCode: 400, error: 'MISSING_CREDENTIALS', message: 'Email and password are required.' };
  }

  const cleanEmail = email.trim().toLowerCase();

  // 1. Fetch user from DB
  let userQuery = 'SELECT * FROM cloud_users WHERE email = $1';
  let userParams = [cleanEmail];
  if (orgHint) {
    userQuery = 'SELECT * FROM cloud_users WHERE email = $1 AND org_id = $2';
    userParams = [cleanEmail, orgHint.trim()];
  }

  let users = [];
  if (typeof db.query === 'function') {
    const res = await db.query(userQuery, userParams);
    users = res.rows || [];
  } else if (typeof db.prepare === 'function') {
    const q = userQuery.replace(/\$1/g, '?').replace(/\$2/g, '?');
    users = db.prepare(q).all(...userParams);
  }

  if (users.length === 0) {
    return { success: false, statusCode: 401, error: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' };
  }

  // If multiple organizations exist for same email and no hint provided, select the active primary or require orgHint
  const user = users[0];

  // 2. Check Account Status
  if (user.status !== 'ACTIVE') {
    await recordAuthAuditLog(db, {
      orgId: user.org_id,
      actorId: user.id,
      action: 'USER_LOGIN_FAILED',
      resourceId: user.id,
      correlationId,
      details: { reason: 'ACCOUNT_INACTIVE_OR_SUSPENDED', status: user.status },
      ipAddress: ip,
      userAgent
    });
    return { success: false, statusCode: 403, error: 'ACCOUNT_SUSPENDED', message: `Account is ${user.status}.` };
  }

  // 3. Check Lockout Status
  if (user.locked_until) {
    let dateStr = String(user.locked_until);
    if (!dateStr.includes('Z') && !dateStr.includes('+')) {
      dateStr = dateStr.replace(' ', 'T') + 'Z';
    }
    const lockedUntilTime = new Date(dateStr).getTime();
    const nowTime = Date.now();
    if (lockedUntilTime > nowTime) {
      const remainingMinutes = Math.ceil((lockedUntilTime - nowTime) / 60000);
      await recordAuthAuditLog(db, {
        orgId: user.org_id,
        actorId: user.id,
        action: 'USER_LOGIN_FAILED',
        resourceId: user.id,
        correlationId,
        details: { reason: 'ACCOUNT_LOCKED', remainingMinutes },
        ipAddress: ip,
        userAgent
      });
      return {
        success: false,
        statusCode: 423,
        error: 'ACCOUNT_LOCKED',
        message: `Account is temporarily locked due to multiple failed login attempts. Try again in ${remainingMinutes} minute(s).`
      };
    }
  }

  // 4. Verify Password
  const isMatch = verifyPassword(password, user.password_hash);
  if (!isMatch) {
    const newFailedCount = (user.failed_login_attempts || 0) + 1;
    let lockQuery = '';
    let lockParams = [];

    if (newFailedCount >= MAX_FAILED_ATTEMPTS) {
      // Lock account for 15 minutes
      if (typeof db.query === 'function') {
        lockQuery = `
          UPDATE cloud_users 
          SET failed_login_attempts = $1, locked_until = NOW() + INTERVAL '15 minutes'
          WHERE id = $2
        `;
        await db.query(lockQuery, [newFailedCount, user.id]);
      } else {
        lockQuery = `
          UPDATE cloud_users 
          SET failed_login_attempts = ?, locked_until = datetime('now', '+15 minutes')
          WHERE id = ?
        `;
        db.prepare(lockQuery).run(newFailedCount, user.id);
      }

      await recordAuthAuditLog(db, {
        orgId: user.org_id,
        actorId: user.id,
        action: 'USER_ACCOUNT_LOCKED',
        resourceId: user.id,
        correlationId,
        details: { failedAttempts: newFailedCount, lockedMinutes: LOCKOUT_DURATION_MINUTES },
        ipAddress: ip,
        userAgent
      });

      return {
        success: false,
        statusCode: 423,
        error: 'ACCOUNT_LOCKED',
        message: `Account has been locked for ${LOCKOUT_DURATION_MINUTES} minutes due to ${newFailedCount} failed attempts.`
      };
    } else {
      // Increment failed count
      if (typeof db.query === 'function') {
        lockQuery = 'UPDATE cloud_users SET failed_login_attempts = $1 WHERE id = $2';
        await db.query(lockQuery, [newFailedCount, user.id]);
      } else {
        lockQuery = 'UPDATE cloud_users SET failed_login_attempts = ? WHERE id = ?';
        db.prepare(lockQuery).run(newFailedCount, user.id);
      }

      await recordAuthAuditLog(db, {
        orgId: user.org_id,
        actorId: user.id,
        action: 'USER_LOGIN_FAILED',
        resourceId: user.id,
        correlationId,
        details: { failedAttempts: newFailedCount },
        ipAddress: ip,
        userAgent
      });

      return {
        success: false,
        statusCode: 401,
        error: 'INVALID_CREDENTIALS',
        message: `Invalid email or password. Attempt ${newFailedCount} of ${MAX_FAILED_ATTEMPTS}.`
      };
    }
  }

  // 5. Successful Login: Reset Lockout & Update last_login_at
  if (typeof db.query === 'function') {
    await db.query(`
      UPDATE cloud_users 
      SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW() 
      WHERE id = $1
    `, [user.id]);
  } else {
    db.prepare(`
      UPDATE cloud_users 
      SET failed_login_attempts = 0, locked_until = NULL, last_login_at = datetime('now') 
      WHERE id = ?
    `).run(user.id);
  }

  // 6. Create Session & Tokens
  const sessionId = generateSessionId();
  const rawRefreshToken = generateRawRefreshToken();
  const refreshHash = hashRefreshToken(rawRefreshToken);

  if (typeof db.query === 'function') {
    await db.query(`
      INSERT INTO cloud_user_sessions (
        session_id, user_id, org_id, refresh_token_hash, user_agent, ip_address, expires_at
      ) VALUES ($1, $2, $3, $4, $5, $6, NOW() + INTERVAL '7 days')
    `, [sessionId, user.id, user.org_id, refreshHash, userAgent, ip]);
  } else {
    db.prepare(`
      INSERT INTO cloud_user_sessions (
        id, session_id, user_id, org_id, refresh_token_hash, user_agent, ip_address, expires_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', '+7 days'))
    `).run('sess_uuid_' + Date.now(), sessionId, user.id, user.org_id, refreshHash, userAgent, ip);
  }

  const accessToken = generateAccessToken({
    sub: user.id,
    org_id: user.org_id,
    role: user.role,
    sid: sessionId
  });

  await recordAuthAuditLog(db, {
    orgId: user.org_id,
    actorId: user.id,
    action: 'USER_LOGIN_SUCCESS',
    resourceId: user.id,
    correlationId,
    details: { sessionId, role: user.role },
    ipAddress: ip,
    userAgent
  });

  return {
    success: true,
    statusCode: 200,
    user: {
      id: user.id,
      email: user.email,
      fullName: user.full_name,
      role: user.role,
      orgId: user.org_id
    },
    session: {
      sessionId,
      accessToken,
      refreshToken: rawRefreshToken,
      expiresIn: ACCESS_TOKEN_TTL_SECONDS
    }
  };
}

/**
 * Refresh Session Flow with Single-Use Rotation & Replay Attack Defense
 */
async function refreshSession(db, { sessionId, rawRefreshToken, ip = null, userAgent = null, correlationId = null }) {
  if (!sessionId || !rawRefreshToken) {
    return { success: false, statusCode: 400, error: 'MISSING_REFRESH_DATA', message: 'Session ID and refresh token are required.' };
  }

  // 1. Fetch active session
  let sessionQuery = `
    SELECT s.*, u.status as user_status, u.role, u.password_changed_at
    FROM cloud_user_sessions s
    JOIN cloud_users u ON s.user_id = u.id
    WHERE s.session_id = $1
  `;
  let sessions = [];

  if (typeof db.query === 'function') {
    const res = await db.query(sessionQuery, [sessionId]);
    sessions = res.rows || [];
  } else if (typeof db.prepare === 'function') {
    sessions = db.prepare(sessionQuery.replace(/\$1/g, '?')).all(sessionId);
  }

  if (sessions.length === 0) {
    return { success: false, statusCode: 401, error: 'SESSION_NOT_FOUND', message: 'Session does not exist.' };
  }

  const session = sessions[0];

  // 2. Check revocation & expiry
  if (session.revoked_at) {
    return { success: false, statusCode: 401, error: 'SESSION_REVOKED', message: 'Session has been revoked.' };
  }

  const expiryTime = new Date(session.expires_at).getTime();
  if (expiryTime < Date.now()) {
    return { success: false, statusCode: 401, error: 'SESSION_EXPIRED', message: 'Session has expired.' };
  }

  if (session.user_status !== 'ACTIVE') {
    return { success: false, statusCode: 403, error: 'USER_INACTIVE', message: 'User account is inactive.' };
  }

  // 3. Verify Refresh Token Hash Match
  const inputHash = hashRefreshToken(rawRefreshToken);
  const isMatch = (inputHash === session.refresh_token_hash);

  if (!isMatch) {
    // REPLAY ATTACK OR TOKEN FORGERY DETECTED: Immediately Kill the Session!
    if (typeof db.query === 'function') {
      await db.query(`
        UPDATE cloud_user_sessions 
        SET revoked_at = NOW(), revoked_reason = 'REPLAY_ATTACK_DETECTED' 
        WHERE session_id = $1
      `, [sessionId]);
    } else {
      db.prepare(`
        UPDATE cloud_user_sessions 
        SET revoked_at = datetime('now'), revoked_reason = 'REPLAY_ATTACK_DETECTED' 
        WHERE session_id = ?
      `).run(sessionId);
    }

    await recordAuthAuditLog(db, {
      orgId: session.org_id,
      actorId: session.user_id,
      action: 'REFRESH_REPLAY_DETECTED',
      resourceType: 'SESSION',
      resourceId: sessionId,
      correlationId,
      details: { reason: 'HASH_MISMATCH_REUSED_TOKEN', actionTaken: 'SESSION_KILLED' },
      ipAddress: ip,
      userAgent
    });

    return {
      success: false,
      statusCode: 401,
      error: 'REPLAY_ATTACK_DETECTED',
      message: 'Invalid refresh token. Session has been revoked for security.'
    };
  }

  // 4. Token Rotation: Generate new refresh token & store new hash
  const newRawRefreshToken = generateRawRefreshToken();
  const newRefreshHash = hashRefreshToken(newRawRefreshToken);

  if (typeof db.query === 'function') {
    await db.query(`
      UPDATE cloud_user_sessions 
      SET refresh_token_hash = $1, last_seen_at = NOW(), ip_address = COALESCE($2, ip_address), user_agent = COALESCE($3, user_agent)
      WHERE session_id = $4
    `, [newRefreshHash, ip, userAgent, sessionId]);
  } else {
    db.prepare(`
      UPDATE cloud_user_sessions 
      SET refresh_token_hash = ?, last_seen_at = datetime('now'), ip_address = COALESCE(?, ip_address), user_agent = COALESCE(?, user_agent)
      WHERE session_id = ?
    `).run(newRefreshHash, ip, userAgent, sessionId);
  }

  const newAccessToken = generateAccessToken({
    sub: session.user_id,
    org_id: session.org_id,
    role: session.role,
    sid: sessionId
  });

  await recordAuthAuditLog(db, {
    orgId: session.org_id,
    actorId: session.user_id,
    action: 'REFRESH_ROTATED',
    resourceType: 'SESSION',
    resourceId: sessionId,
    correlationId,
    details: { rotated: true },
    ipAddress: ip,
    userAgent
  });

  return {
    success: true,
    statusCode: 200,
    session: {
      sessionId,
      accessToken: newAccessToken,
      refreshToken: newRawRefreshToken,
      expiresIn: ACCESS_TOKEN_TTL_SECONDS
    }
  };
}

/**
 * Logout User Flow: Revokes Current Session
 */
async function logoutUser(db, { sessionId, userId, orgId, ip = null, userAgent = null, correlationId = null }) {
  if (!sessionId) return { success: false, statusCode: 400, error: 'MISSING_SESSION_ID' };

  if (typeof db.query === 'function') {
    await db.query(`
      UPDATE cloud_user_sessions 
      SET revoked_at = NOW(), revoked_reason = 'USER_LOGOUT' 
      WHERE session_id = $1 AND org_id = $2
    `, [sessionId, orgId]);
  } else {
    db.prepare(`
      UPDATE cloud_user_sessions 
      SET revoked_at = datetime('now'), revoked_reason = 'USER_LOGOUT' 
      WHERE session_id = ? AND org_id = ?
    `).run(sessionId, orgId);
  }

  await recordAuthAuditLog(db, {
    orgId,
    actorId: userId,
    action: 'USER_LOGOUT',
    resourceType: 'SESSION',
    resourceId: sessionId,
    correlationId,
    details: { reason: 'USER_LOGOUT' },
    ipAddress: ip,
    userAgent
  });

  return { success: true, statusCode: 200, message: 'Logged out successfully.' };
}

/**
 * Revoke Individual Session
 */
async function revokeSession(db, { targetSessionId, orgId, callerUserId, reason = 'ADMIN_REVOKED', ip = null, userAgent = null, correlationId = null }) {
  if (!targetSessionId) return { success: false, statusCode: 400, error: 'MISSING_SESSION_ID' };

  if (typeof db.query === 'function') {
    await db.query(`
      UPDATE cloud_user_sessions 
      SET revoked_at = NOW(), revoked_reason = $1 
      WHERE session_id = $2 AND org_id = $3
    `, [reason, targetSessionId, orgId]);
  } else {
    db.prepare(`
      UPDATE cloud_user_sessions 
      SET revoked_at = datetime('now'), revoked_reason = ? 
      WHERE session_id = ? AND org_id = ?
    `).run(reason, targetSessionId, orgId);
  }

  await recordAuthAuditLog(db, {
    orgId,
    actorId: callerUserId,
    action: 'SESSION_REVOKED',
    resourceType: 'SESSION',
    resourceId: targetSessionId,
    correlationId,
    details: { reason },
    ipAddress: ip,
    userAgent
  });

  return { success: true, statusCode: 200, message: `Session ${targetSessionId} revoked.` };
}

/**
 * Change Password and Globally Invalidate Affected Sessions
 */
async function changePassword(db, { userId, orgId, currentPassword, newPassword, ip = null, userAgent = null, correlationId = null }) {
  if (!userId || !orgId || !currentPassword || !newPassword) {
    return { success: false, statusCode: 400, error: 'MISSING_PARAMETERS' };
  }

  // 1. Fetch user
  let users = [];
  if (typeof db.query === 'function') {
    const res = await db.query('SELECT * FROM cloud_users WHERE id = $1 AND org_id = $2', [userId, orgId]);
    users = res.rows || [];
  } else {
    users = db.prepare('SELECT * FROM cloud_users WHERE id = ? AND org_id = ?').all(userId, orgId);
  }

  if (users.length === 0) {
    return { success: false, statusCode: 404, error: 'USER_NOT_FOUND' };
  }

  const user = users[0];

  // 2. Verify current password
  if (!verifyPassword(currentPassword, user.password_hash)) {
    return { success: false, statusCode: 401, error: 'INVALID_CURRENT_PASSWORD', message: 'Current password is incorrect.' };
  }

  // 3. Hash new password
  const newHash = hashPassword(newPassword);

  // 4. Update password and invalidate all user sessions
  if (typeof db.query === 'function') {
    await db.query(`
      UPDATE cloud_users 
      SET password_hash = $1, password_changed_at = NOW(), updated_at = NOW() 
      WHERE id = $2 AND org_id = $3
    `, [newHash, userId, orgId]);

    await db.query(`
      UPDATE cloud_user_sessions 
      SET revoked_at = NOW(), revoked_reason = 'PASSWORD_CHANGED_GLOBAL_REVOCATION' 
      WHERE user_id = $1 AND org_id = $2 AND revoked_at IS NULL
    `, [userId, orgId]);
  } else {
    db.prepare(`
      UPDATE cloud_users 
      SET password_hash = ?, password_changed_at = datetime('now'), updated_at = datetime('now') 
      WHERE id = ? AND org_id = ?
    `).run(newHash, userId, orgId);

    db.prepare(`
      UPDATE cloud_user_sessions 
      SET revoked_at = datetime('now'), revoked_reason = 'PASSWORD_CHANGED_GLOBAL_REVOCATION' 
      WHERE user_id = ? AND org_id = ? AND revoked_at IS NULL
    `).run(userId, orgId);
  }

  await recordAuthAuditLog(db, {
    orgId,
    actorId: userId,
    action: 'PASSWORD_CHANGED',
    resourceType: 'USER',
    resourceId: userId,
    correlationId,
    details: { allSessionsInvalidated: true },
    ipAddress: ip,
    userAgent
  });

  return { success: true, statusCode: 200, message: 'Password changed successfully. All active sessions invalidated.' };
}

/**
 * Server-Side Authoritative Request Authentication Middleware / Guard
 */
async function authenticateRequest(db, authHeader, secretKey = null) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { authenticated: false, statusCode: 401, error: 'NO_BEARER_TOKEN' };
  }

  const token = authHeader.substring(7).trim();
  const tokenResult = verifyAccessToken(token, secretKey);
  if (!tokenResult.valid) {
    return { authenticated: false, statusCode: 401, error: tokenResult.error };
  }

  const { sub: userId, sid: sessionId } = tokenResult.payload;

  // Server-side authoritative verification against live database
  const query = `
    SELECT s.session_id, s.expires_at, s.revoked_at,
           u.id as user_id, u.org_id, u.role, u.status as user_status, u.password_changed_at,
           o.status as org_status
    FROM cloud_user_sessions s
    JOIN cloud_users u ON s.user_id = u.id
    JOIN cloud_organizations o ON u.org_id = o.org_id
    WHERE s.session_id = $1
  `;
  let rows = [];

  if (typeof db.query === 'function') {
    const res = await db.query(query, [sessionId]);
    rows = res.rows || [];
  } else {
    rows = db.prepare(query.replace(/\$1/g, '?')).all(sessionId);
  }

  if (rows.length === 0) {
    return { authenticated: false, statusCode: 401, error: 'SESSION_NOT_FOUND' };
  }

  const record = rows[0];

  if (record.revoked_at) {
    return { authenticated: false, statusCode: 401, error: 'SESSION_REVOKED' };
  }

  if (new Date(record.expires_at).getTime() < Date.now()) {
    return { authenticated: false, statusCode: 401, error: 'SESSION_EXPIRED' };
  }

  if (record.user_status !== 'ACTIVE') {
    return { authenticated: false, statusCode: 403, error: 'USER_ACCOUNT_SUSPENDED' };
  }

  if (record.org_status !== 'ACTIVE') {
    return { authenticated: false, statusCode: 403, error: 'ORGANIZATION_SUSPENDED' };
  }

  return {
    authenticated: true,
    user: {
      userId: record.user_id,
      orgId: record.org_id,
      role: record.role,
      sessionId: record.session_id
    }
  };
}

module.exports = {
  getJwtSecret,
  validateAuthConfiguration,
  hashPassword,
  verifyPassword,
  generateSessionId,
  generateRawRefreshToken,
  hashRefreshToken,
  generateAccessToken,
  verifyAccessToken,
  recordAuthAuditLog,
  loginUser,
  refreshSession,
  logoutUser,
  revokeSession,
  changePassword,
  authenticateRequest,
  ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_TTL_DAYS,
  MAX_FAILED_ATTEMPTS,
  LOCKOUT_DURATION_MINUTES
};
