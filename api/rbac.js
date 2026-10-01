/**
 * AMAN CASHIER SAAS — RBAC CORE & PERMISSION ENGINE
 * PHASE 2C-2A: Core Roles, Granular Permissions, and Middleware Guards
 * 
 * Rules:
 * 1. Strict Deny by default.
 * 2. Immutable/Frozen permission sets.
 * 3. Authority derived strictly from Authenticated Actor (never client-supplied role/org/user).
 * 4. Executive Roles: PLATFORM_ADMIN, ORG_OWNER, STORE_MANAGER, AUDITOR / VIEWER.
 *    (ORG_ADMIN is an OPEN DECISION and intentionally omitted from executable roles).
 */

const ROLE_SCOPES = Object.freeze({
  PLATFORM_ADMIN: 'PLATFORM_SCOPE',
  ORG_OWNER: 'ORGANIZATION_GLOBAL_SCOPE',
  STORE_MANAGER: 'STORE_SCOPED',
  AUDITOR: 'ORGANIZATION_READONLY_SCOPE',
  VIEWER: 'ORGANIZATION_READONLY_SCOPE'
});

const PERMISSIONS = Object.freeze({
  // Organization Management
  ORG_READ: 'org.read',
  ORG_UPDATE: 'org.update',

  // Store Management
  STORES_READ: 'stores.read',
  STORES_CREATE: 'stores.create',
  STORES_UPDATE: 'stores.update',
  STORES_DISABLE: 'stores.disable',

  // Store Access Authorization
  STORE_ACCESS_READ: 'store_access.read',
  STORE_ACCESS_GRANT: 'store_access.grant',
  STORE_ACCESS_REVOKE: 'store_access.revoke',

  // User Management
  USERS_READ: 'users.read',
  USERS_CREATE: 'users.create',
  USERS_UPDATE: 'users.update',
  USERS_DISABLE: 'users.disable',

  // Reports & Analytics (Read-Only)
  REPORTS_SALES_READ: 'reports.sales.read',
  REPORTS_INVENTORY_READ: 'reports.inventory.read',
  REPORTS_SHIFTS_READ: 'reports.shifts.read',

  // Device & Pairing Management
  DEVICES_READ: 'devices.read',
  DEVICES_REVOKE: 'devices.revoke',

  // Audit Logs
  AUDIT_READ: 'audit.read',

  // Platform Level Only
  LICENSES_ISSUE: 'licenses.issue',
  LICENSES_REVOKE: 'licenses.revoke'
});

const ROLE_PERMISSIONS_MAP = Object.freeze({
  PLATFORM_ADMIN: Object.freeze(new Set([
    PERMISSIONS.ORG_READ,
    PERMISSIONS.ORG_UPDATE,
    PERMISSIONS.STORES_READ,
    PERMISSIONS.STORES_CREATE,
    PERMISSIONS.STORES_UPDATE,
    PERMISSIONS.STORES_DISABLE,
    PERMISSIONS.STORE_ACCESS_READ,
    PERMISSIONS.STORE_ACCESS_GRANT,
    PERMISSIONS.STORE_ACCESS_REVOKE,
    PERMISSIONS.USERS_READ,
    PERMISSIONS.USERS_CREATE,
    PERMISSIONS.USERS_UPDATE,
    PERMISSIONS.USERS_DISABLE,
    PERMISSIONS.REPORTS_SALES_READ,
    PERMISSIONS.REPORTS_INVENTORY_READ,
    PERMISSIONS.REPORTS_SHIFTS_READ,
    PERMISSIONS.DEVICES_READ,
    PERMISSIONS.DEVICES_REVOKE,
    PERMISSIONS.AUDIT_READ,
    PERMISSIONS.LICENSES_ISSUE,
    PERMISSIONS.LICENSES_REVOKE
  ])),

  ORG_OWNER: Object.freeze(new Set([
    PERMISSIONS.ORG_READ,
    PERMISSIONS.ORG_UPDATE,
    PERMISSIONS.STORES_READ,
    PERMISSIONS.STORES_CREATE,
    PERMISSIONS.STORES_UPDATE,
    PERMISSIONS.STORES_DISABLE,
    PERMISSIONS.STORE_ACCESS_READ,
    PERMISSIONS.STORE_ACCESS_GRANT,
    PERMISSIONS.STORE_ACCESS_REVOKE,
    PERMISSIONS.USERS_READ,
    PERMISSIONS.USERS_CREATE,
    PERMISSIONS.USERS_UPDATE,
    PERMISSIONS.USERS_DISABLE,
    PERMISSIONS.REPORTS_SALES_READ,
    PERMISSIONS.REPORTS_INVENTORY_READ,
    PERMISSIONS.REPORTS_SHIFTS_READ,
    PERMISSIONS.DEVICES_READ,
    PERMISSIONS.DEVICES_REVOKE,
    PERMISSIONS.AUDIT_READ
  ])),

  STORE_MANAGER: Object.freeze(new Set([
    PERMISSIONS.STORES_READ,
    PERMISSIONS.REPORTS_SALES_READ,
    PERMISSIONS.REPORTS_INVENTORY_READ,
    PERMISSIONS.REPORTS_SHIFTS_READ,
    PERMISSIONS.DEVICES_READ
  ])),

  AUDITOR: Object.freeze(new Set([
    PERMISSIONS.ORG_READ,
    PERMISSIONS.STORES_READ,
    PERMISSIONS.STORE_ACCESS_READ,
    PERMISSIONS.USERS_READ,
    PERMISSIONS.REPORTS_SALES_READ,
    PERMISSIONS.REPORTS_INVENTORY_READ,
    PERMISSIONS.REPORTS_SHIFTS_READ,
    PERMISSIONS.DEVICES_READ,
    PERMISSIONS.AUDIT_READ
  ])),

  VIEWER: Object.freeze(new Set([
    PERMISSIONS.ORG_READ,
    PERMISSIONS.STORES_READ,
    PERMISSIONS.STORE_ACCESS_READ,
    PERMISSIONS.USERS_READ,
    PERMISSIONS.REPORTS_SALES_READ,
    PERMISSIONS.REPORTS_INVENTORY_READ,
    PERMISSIONS.REPORTS_SHIFTS_READ,
    PERMISSIONS.DEVICES_READ,
    PERMISSIONS.AUDIT_READ
  ]))
});

/**
 * Normalize and sanitize role name
 */
function normalizeRole(rawRole) {
  if (!rawRole || typeof rawRole !== 'string') return null;
  const normalized = rawRole.trim().toUpperCase();
  return ROLE_PERMISSIONS_MAP.hasOwnProperty(normalized) ? normalized : null;
}

/**
 * Check if a role is a valid, executable RBAC role
 */
function isValidRole(rawRole) {
  const norm = normalizeRole(rawRole);
  return norm !== null;
}

/**
 * Check if a given role has a specific permission
 * Deny by default if role or permission is unknown.
 */
function hasPermission(rawRole, permission) {
  if (!permission || typeof permission !== 'string') return false;
  const role = normalizeRole(rawRole);
  if (!role) return false;

  const permissionsSet = ROLE_PERMISSIONS_MAP[role];
  if (!permissionsSet) return false;

  return permissionsSet.has(permission);
}

/**
 * Retrieve all granted permissions for a given role
 */
function getRolePermissions(rawRole) {
  const role = normalizeRole(rawRole);
  if (!role) return [];
  const permissionsSet = ROLE_PERMISSIONS_MAP[role];
  return permissionsSet ? Array.from(permissionsSet) : [];
}

/**
 * Get the architectural scope of a given role
 */
function getRoleScope(rawRole) {
  const role = normalizeRole(rawRole);
  if (!role) return null;
  return ROLE_SCOPES[role] || null;
}

/**
 * Authoritative check taking authenticated actor context
 */
function checkPermissionForActor(authActor, permission) {
  if (!authActor || typeof authActor !== 'object') {
    return { allowed: false, reason: 'UNAUTHENTICATED_ACTOR' };
  }
  const role = authActor.role;
  if (!role) {
    return { allowed: false, reason: 'NO_ROLE_ASSIGNED' };
  }
  const allowed = hasPermission(role, permission);
  return {
    allowed,
    role: normalizeRole(role),
    scope: getRoleScope(role),
    reason: allowed ? 'GRANTED' : 'INSUFFICIENT_PERMISSIONS'
  };
}

/**
 * Middleware builder: Enforce specific role requirement
 */
function requireRole(allowedRoles = []) {
  const validRolesSet = new Set(
    (Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles])
      .map(r => normalizeRole(r))
      .filter(Boolean)
  );

  return (req, res, next) => {
    if (!req.auth || !req.auth.role) {
      return res.status(401).json({
        success: false,
        error: 'UNAUTHENTICATED',
        message: 'Authentication is required.'
      });
    }

    const currentRole = normalizeRole(req.auth.role);
    if (!currentRole || !validRolesSet.has(currentRole)) {
      return res.status(403).json({
        success: false,
        error: 'ROLE_FORBIDDEN',
        message: 'Your role is not authorized to perform this action.'
      });
    }

    if (typeof next === 'function') next();
  };
}

/**
 * Middleware builder: Enforce specific granular permission requirement
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.auth || !req.auth.role) {
      return res.status(401).json({
        success: false,
        error: 'UNAUTHENTICATED',
        message: 'Authentication is required.'
      });
    }

    const currentRole = req.auth.role;
    const allowed = hasPermission(currentRole, permission);

    if (!allowed) {
      return res.status(403).json({
        success: false,
        error: 'PERMISSION_DENIED',
        requiredPermission: permission,
        message: `Permission ${permission} is denied for current role.`
      });
    }

    if (typeof next === 'function') next();
  };
}

module.exports = {
  PERMISSIONS,
  ROLE_SCOPES,
  normalizeRole,
  isValidRole,
  hasPermission,
  getRolePermissions,
  getRoleScope,
  checkPermissionForActor,
  requireRole,
  requirePermission
};
