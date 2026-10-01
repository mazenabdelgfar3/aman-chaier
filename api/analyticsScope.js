/**
 * AMAN CASHIER SAAS — ANALYTICS, INVENTORY & AUDIT SCOPE ENGINE
 * PHASE 2E-3: Multi-Store Financial Analytics, Shift Auditing, Inventory Overview & Immutable Audit Trail
 * 
 * Rules:
 * 1. Strict Server-Derived Tenant Context (callerActor.orgId).
 * 2. Strict Store Scoping: STORE_MANAGER restricted strictly to assigned stores in cloud_user_store_access.
 * 3. Exact SQL Parameterization — Zero string concatenation.
 * 4. Bounded Pagination: default 50, maximum 100.
 * 5. Safe Mathematical Computation: Zero division protection.
 * 6. Audit Trail Sanitization: Redaction of any sensitive credentials.
 */

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
 * Helper to parse and enforce bounded pagination
 */
function parsePagination(reqPage, reqLimit) {
  const page = Math.max(1, parseInt(reqPage, 10) || 1);
  const rawLimit = parseInt(reqLimit, 10) || 50;
  const limit = Math.min(100, Math.max(1, rawLimit));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

/**
 * Resolves authorized store scope for the caller actor
 * Returns { allowed: true, storeIds: [...], orgId } or { allowed: false, statusCode, error, message }
 */
async function resolveAuthorizedStoreScope(db, callerActor, requestedStoreId) {
  if (!callerActor || typeof callerActor !== 'object' || !callerActor.userId) {
    return { allowed: false, statusCode: 401, error: 'UNAUTHENTICATED', message: 'Authentication required.' };
  }

  const role = rbac.normalizeRole(callerActor.role);
  if (!role) {
    return { allowed: false, statusCode: 403, error: 'INVALID_OR_UNKNOWN_ROLE', message: 'Unrecognized user role.' };
  }

  const { orgId } = callerActor;

  // 1. If explicit store_id requested, validate access strictly
  if (requestedStoreId && typeof requestedStoreId === 'string' && requestedStoreId.trim()) {
    const targetStoreId = requestedStoreId.trim();
    const accessCheck = await storeScope.validateStoreAccess(db, callerActor, targetStoreId);
    if (!accessCheck.allowed) {
      return {
        allowed: false,
        statusCode: accessCheck.statusCode,
        error: accessCheck.error || 'ACCESS_DENIED',
        message: accessCheck.message || 'Access to store denied.'
      };
    }
    return {
      allowed: true,
      orgId,
      storeIds: [targetStoreId],
      isSingleStore: true
    };
  }

  // 2. No explicit store_id requested -> Determine all allowed stores
  const accessibleStores = await storeScope.getUserAccessibleStores(db, callerActor);
  const storeIds = accessibleStores
    .filter(s => s.status !== 'DECOMMISSIONED')
    .map(s => s.store_id);

  return {
    allowed: true,
    orgId,
    storeIds,
    isSingleStore: false
  };
}

/**
 * Build SQL IN clause safely with indexed parameters
 */
function buildInClause(storeIds, paramOffset = 1) {
  if (!storeIds || storeIds.length === 0) return { clause: '1=0', params: [] };
  const placeholders = storeIds.map((_, idx) => `$${paramOffset + idx}`).join(', ');
  return { clause: `IN (${placeholders})`, params: [...storeIds] };
}

// =============================================================================
// 1. SALES & FINANCIAL ANALYTICS OVERVIEW
// =============================================================================
async function getAnalyticsOverview(db, { callerActor, storeIdFilter, startDate, endDate }) {
  const scope = await resolveAuthorizedStoreScope(db, callerActor, storeIdFilter);
  if (!scope.allowed) {
    return { success: false, statusCode: scope.statusCode, error: scope.error, message: scope.message };
  }

  if (scope.storeIds.length === 0) {
    return {
      success: true,
      statusCode: 200,
      scope: { orgId: scope.orgId, storeIds: [] },
      summary: {
        invoicesCount: 0,
        totalSalesCents: 0,
        discountCents: 0,
        returnsCents: 0,
        netSalesCents: 0,
        cogsCents: 0,
        netProfitCents: 0,
        profitMarginPct: 0,
        averageTicketCents: 0
      },
      paymentMethods: { cashCents: 0, cardCents: 0, instapayCents: 0, creditCents: 0 }
    };
  }

  const inHelper = buildInClause(scope.storeIds, 2);
  const queryParams = [scope.orgId, ...inHelper.params];

  let dateFilterSql = '';
  if (startDate) {
    queryParams.push(startDate);
    dateFilterSql += ` AND created_at >= $${queryParams.length}`;
  }
  if (endDate) {
    queryParams.push(endDate);
    dateFilterSql += ` AND created_at <= $${queryParams.length}`;
  }

  // 1. Fetch Invoices summary
  const invoicesSql = `
    SELECT 
      COUNT(id) AS invoices_count,
      COALESCE(SUM(final_amount_cents), 0) AS gross_sales_cents,
      COALESCE(SUM(discount_cents), 0) AS discount_cents,
      COALESCE(SUM(CASE WHEN LOWER(TRIM(payment_method)) IN ('cash', 'نقدي', 'كاش') THEN final_amount_cents ELSE 0 END), 0) AS cash_cents,
      COALESCE(SUM(CASE WHEN LOWER(TRIM(payment_method)) IN ('card', 'بطاقة', 'فيزا', 'visa') THEN final_amount_cents ELSE 0 END), 0) AS card_cents,
      COALESCE(SUM(CASE WHEN LOWER(TRIM(payment_method)) IN ('instapay', 'vodafone_cash', 'wallet', 'انستاباي', 'محفظة', 'فودافون كاش') THEN final_amount_cents ELSE 0 END), 0) AS instapay_cents,
      COALESCE(SUM(CASE WHEN LOWER(TRIM(payment_method)) IN ('credit', 'آجل', 'اجل', 'على الحساب') THEN final_amount_cents ELSE 0 END), 0) AS credit_cents
    FROM cloud_invoices
    WHERE org_id = $1 AND store_id ${inHelper.clause} AND status = 'COMPLETED' ${dateFilterSql}
  `;
  const invoiceRows = await executeDbQuery(db, invoicesSql, queryParams);
  const invSummary = invoiceRows[0] || {};

  // 2. Fetch Returns summary from cash movements
  const returnsSql = `
    SELECT COALESCE(SUM(amount_cents), 0) AS total_returns_cents
    FROM cloud_cash_movements
    WHERE org_id = $1 AND store_id ${inHelper.clause} AND movement_type = 'RETURN' ${dateFilterSql}
  `;
  const returnRows = await executeDbQuery(db, returnsSql, queryParams);
  const totalReturnsCents = Number(returnRows[0]?.total_returns_cents) || 0;

  // 3. Fetch COGS from invoice items
  const cogsSql = `
    SELECT COALESCE(SUM(
      COALESCE(NULLIF(unit_cost_cents, 0), CAST(unit_price_cents * 0.70 AS BIGINT)) * quantity
    ), 0) AS total_cogs_cents
    FROM cloud_invoice_items
    WHERE org_id = $1 AND store_id ${inHelper.clause} ${dateFilterSql}
  `;
  const cogsRows = await executeDbQuery(db, cogsSql, queryParams);
  const totalCogsCents = Number(cogsRows[0]?.total_cogs_cents) || 0;

  const invoicesCount = Number(invSummary.invoices_count) || 0;
  const grossSalesCents = Number(invSummary.gross_sales_cents) || 0;
  const discountCents = Number(invSummary.discount_cents) || 0;
  const netSalesCents = Math.max(0, grossSalesCents - totalReturnsCents);
  const netProfitCents = netSalesCents - totalCogsCents;
  const profitMarginPct = netSalesCents > 0 ? Math.round((netProfitCents / netSalesCents) * 1000) / 10 : 0;
  const averageTicketCents = invoicesCount > 0 ? Math.round(grossSalesCents / invoicesCount) : 0;

  return {
    success: true,
    statusCode: 200,
    scope: { orgId: scope.orgId, storeIds: scope.storeIds },
    summary: {
      invoicesCount,
      totalSalesCents: grossSalesCents,
      discountCents,
      returnsCents: totalReturnsCents,
      netSalesCents,
      cogsCents: totalCogsCents,
      netProfitCents,
      profitMarginPct,
      averageTicketCents
    },
    paymentMethods: {
      cashCents: Number(invSummary.cash_cents) || 0,
      cardCents: Number(invSummary.card_cents) || 0,
      instapayCents: Number(invSummary.instapay_cents) || 0,
      creditCents: Number(invSummary.credit_cents) || 0
    }
  };
}

// =============================================================================
// 2. INVOICE ANALYTICS LISTING & DETAILS
// =============================================================================
async function getInvoiceAnalytics(db, { callerActor, storeIdFilter, paymentMethod, page, limit, startDate, endDate }) {
  const scope = await resolveAuthorizedStoreScope(db, callerActor, storeIdFilter);
  if (!scope.allowed) {
    return { success: false, statusCode: scope.statusCode, error: scope.error, message: scope.message };
  }

  const { page: currPage, limit: currLimit, offset } = parsePagination(page, limit);

  if (scope.storeIds.length === 0) {
    return {
      success: true,
      statusCode: 200,
      pagination: { page: currPage, limit: currLimit, total: 0, totalPages: 0 },
      invoices: []
    };
  }

  const inHelper = buildInClause(scope.storeIds, 2);
  const queryParams = [scope.orgId, ...inHelper.params];

  let filtersSql = '';
  if (paymentMethod && typeof paymentMethod === 'string' && paymentMethod.trim()) {
    queryParams.push(paymentMethod.trim().toLowerCase());
    filtersSql += ` AND LOWER(payment_method) = $${queryParams.length}`;
  }
  if (startDate) {
    queryParams.push(startDate);
    filtersSql += ` AND created_at >= $${queryParams.length}`;
  }
  if (endDate) {
    queryParams.push(endDate);
    filtersSql += ` AND created_at <= $${queryParams.length}`;
  }

  // Count total matching invoices
  const countSql = `
    SELECT COUNT(id) AS total_count 
    FROM cloud_invoices 
    WHERE org_id = $1 AND store_id ${inHelper.clause} ${filtersSql}
  `;
  const countRows = await executeDbQuery(db, countSql, queryParams);
  const total = Number(countRows[0]?.total_count) || 0;
  const totalPages = Math.ceil(total / currLimit);

  // Fetch paginated records
  const listParams = [...queryParams, currLimit, offset];
  const listSql = `
    SELECT 
      id,
      org_id,
      store_id,
      device_id,
      invoice_id_local,
      invoice_number,
      shift_id_local,
      cashier_name,
      customer_name,
      subtotal_cents,
      discount_cents,
      final_amount_cents,
      paid_amount_cents,
      change_amount_cents,
      payment_method,
      status,
      created_at
    FROM cloud_invoices
    WHERE org_id = $1 AND store_id ${inHelper.clause} ${filtersSql}
    ORDER BY created_at DESC, id DESC
    LIMIT $${listParams.length - 1} OFFSET $${listParams.length}
  `;
  const invoices = await executeDbQuery(db, listSql, listParams);

  return {
    success: true,
    statusCode: 200,
    pagination: { page: currPage, limit: currLimit, total, totalPages },
    invoices
  };
}

async function getInvoiceDetails(db, { callerActor, invoiceId, storeIdFilter }) {
  if (!invoiceId || typeof invoiceId !== 'string' || !invoiceId.trim()) {
    return { success: false, statusCode: 400, error: 'INVALID_INVOICE_ID', message: 'Invoice ID is required.' };
  }

  const scope = await resolveAuthorizedStoreScope(db, callerActor, storeIdFilter);
  if (!scope.allowed) {
    return { success: false, statusCode: scope.statusCode, error: scope.error, message: scope.message };
  }

  if (scope.storeIds.length === 0) {
    return { success: false, statusCode: 404, error: 'INVOICE_NOT_FOUND', message: 'Invoice not found.' };
  }

  const inHelper = buildInClause(scope.storeIds, 4);
  const invoiceSql = `
    SELECT 
      id, org_id, store_id, device_id, invoice_id_local, invoice_number,
      shift_id_local, cashier_name, customer_id, customer_name,
      subtotal_cents, discount_cents, final_amount_cents, paid_amount_cents,
      change_amount_cents, payment_method, status, created_at, synced_at
    FROM cloud_invoices
    WHERE org_id = $1 AND (invoice_id_local = $2 OR invoice_number = $3) AND store_id ${inHelper.clause}
    LIMIT 1
  `;
  const rows = await executeDbQuery(db, invoiceSql, [scope.orgId, invoiceId.trim(), invoiceId.trim(), ...inHelper.params]);
  if (rows.length === 0) {
    return { success: false, statusCode: 404, error: 'INVOICE_NOT_FOUND', message: 'Invoice not found.' };
  }

  const invoice = rows[0];

  // Fetch Line Items
  const itemsSql = `
    SELECT 
      id, product_id, product_name, barcode, unit_cost_cents, unit_price_cents, quantity, subtotal_cents, created_at
    FROM cloud_invoice_items
    WHERE org_id = $1 AND store_id = $2 AND invoice_id_local = $3
    ORDER BY created_at ASC
  `;
  const items = await executeDbQuery(db, itemsSql, [scope.orgId, invoice.store_id, invoice.invoice_id_local]);

  return {
    success: true,
    statusCode: 200,
    invoice: {
      ...invoice,
      items
    }
  };
}

// =============================================================================
// 3. SHIFT RECONCILIATION & CASH DRAWER AUDITING
// =============================================================================
async function getShiftAnalytics(db, { callerActor, storeIdFilter, statusFilter, page, limit, startDate, endDate }) {
  const scope = await resolveAuthorizedStoreScope(db, callerActor, storeIdFilter);
  if (!scope.allowed) {
    return { success: false, statusCode: scope.statusCode, error: scope.error, message: scope.message };
  }

  const { page: currPage, limit: currLimit, offset } = parsePagination(page, limit);

  if (scope.storeIds.length === 0) {
    return {
      success: true,
      statusCode: 200,
      pagination: { page: currPage, limit: currLimit, total: 0, totalPages: 0 },
      shifts: []
    };
  }

  const inHelper = buildInClause(scope.storeIds, 2);
  const queryParams = [scope.orgId, ...inHelper.params];

  let filtersSql = '';
  if (statusFilter && typeof statusFilter === 'string' && statusFilter.trim()) {
    queryParams.push(statusFilter.trim().toUpperCase());
    filtersSql += ` AND status = $${queryParams.length}`;
  }
  if (startDate) {
    queryParams.push(startDate);
    filtersSql += ` AND opened_at >= $${queryParams.length}`;
  }
  if (endDate) {
    queryParams.push(endDate);
    filtersSql += ` AND opened_at <= $${queryParams.length}`;
  }

  const countSql = `
    SELECT COUNT(id) AS total_count 
    FROM cloud_shifts 
    WHERE org_id = $1 AND store_id ${inHelper.clause} ${filtersSql}
  `;
  const countRows = await executeDbQuery(db, countSql, queryParams);
  const total = Number(countRows[0]?.total_count) || 0;
  const totalPages = Math.ceil(total / currLimit);

  const listParams = [...queryParams, currLimit, offset];
  const listSql = `
    SELECT 
      id,
      org_id,
      store_id,
      device_id,
      shift_id_local,
      shift_number,
      cashier_id,
      cashier_name,
      opening_cash_cents,
      expected_cash_cents,
      actual_cash_cents,
      difference_cents,
      total_sales_cents,
      total_returns_cents,
      status,
      opened_at,
      closed_at
    FROM cloud_shifts
    WHERE org_id = $1 AND store_id ${inHelper.clause} ${filtersSql}
    ORDER BY opened_at DESC, id DESC
    LIMIT $${listParams.length - 1} OFFSET $${listParams.length}
  `;
  const shifts = await executeDbQuery(db, listSql, listParams);

  return {
    success: true,
    statusCode: 200,
    pagination: { page: currPage, limit: currLimit, total, totalPages },
    shifts
  };
}

async function getShiftDetails(db, { callerActor, shiftId, storeIdFilter }) {
  if (!shiftId || typeof shiftId !== 'string' || !shiftId.trim()) {
    return { success: false, statusCode: 400, error: 'INVALID_SHIFT_ID', message: 'Shift ID is required.' };
  }

  const scope = await resolveAuthorizedStoreScope(db, callerActor, storeIdFilter);
  if (!scope.allowed) {
    return { success: false, statusCode: scope.statusCode, error: scope.error, message: scope.message };
  }

  if (scope.storeIds.length === 0) {
    return { success: false, statusCode: 404, error: 'SHIFT_NOT_FOUND', message: 'Shift not found.' };
  }

  const inHelper = buildInClause(scope.storeIds, 3);
  const shiftSql = `
    SELECT 
      id, org_id, store_id, device_id, shift_id_local, shift_number,
      cashier_id, cashier_name, opening_cash_cents, expected_cash_cents,
      actual_cash_cents, difference_cents, total_sales_cents, total_returns_cents,
      status, opened_at, closed_at, synced_at
    FROM cloud_shifts
    WHERE org_id = $1 AND shift_id_local = $2 AND store_id ${inHelper.clause}
    LIMIT 1
  `;
  const rows = await executeDbQuery(db, shiftSql, [scope.orgId, shiftId.trim(), ...inHelper.params]);
  if (rows.length === 0) {
    return { success: false, statusCode: 404, error: 'SHIFT_NOT_FOUND', message: 'Shift not found.' };
  }

  const shift = rows[0];

  // Fetch associated Cash Movements
  const cashSql = `
    SELECT 
      id, movement_id_local, movement_type, amount_cents, reason, created_by, created_at
    FROM cloud_cash_movements
    WHERE org_id = $1 AND store_id = $2 AND shift_id_local = $3
    ORDER BY created_at ASC
  `;
  const cashMovements = await executeDbQuery(db, cashSql, [scope.orgId, shift.store_id, shift.shift_id_local]);

  return {
    success: true,
    statusCode: 200,
    shift: {
      ...shift,
      cashMovements
    }
  };
}

// =============================================================================
// 4. INVENTORY OVERVIEW & MOVEMENT LEDGER
// =============================================================================
async function getInventoryOverview(db, { callerActor, storeIdFilter, lowStockOnly, search, page, limit }) {
  const scope = await resolveAuthorizedStoreScope(db, callerActor, storeIdFilter);
  if (!scope.allowed) {
    return { success: false, statusCode: scope.statusCode, error: scope.error, message: scope.message };
  }

  const { page: currPage, limit: currLimit, offset } = parsePagination(page, limit);

  if (scope.storeIds.length === 0) {
    return {
      success: true,
      statusCode: 200,
      pagination: { page: currPage, limit: currLimit, total: 0, totalPages: 0 },
      products: []
    };
  }

  const inHelper = buildInClause(scope.storeIds, 2);
  const queryParams = [scope.orgId, ...inHelper.params];

  let filtersSql = '';
  if (lowStockOnly === true || lowStockOnly === 'true' || lowStockOnly === '1') {
    filtersSql += ` AND stock_quantity <= min_stock_alert`;
  }
  if (search && typeof search === 'string' && search.trim()) {
    queryParams.push(`%${search.trim()}%`);
    filtersSql += ` AND (name ILIKE $${queryParams.length} OR barcode ILIKE $${queryParams.length} OR sku ILIKE $${queryParams.length})`;
  }

  const countSql = `
    SELECT COUNT(id) AS total_count 
    FROM cloud_products 
    WHERE org_id = $1 AND store_id ${inHelper.clause} ${filtersSql}
  `;
  const countRows = await executeDbQuery(db, countSql, queryParams);
  const total = Number(countRows[0]?.total_count) || 0;
  const totalPages = Math.ceil(total / currLimit);

  const listParams = [...queryParams, currLimit, offset];
  const listSql = `
    SELECT 
      id,
      org_id,
      store_id,
      device_id,
      product_id_local,
      name,
      barcode,
      sku,
      cost_price_cents,
      selling_price_cents,
      stock_quantity,
      min_stock_alert,
      unit,
      is_active,
      updated_at
    FROM cloud_products
    WHERE org_id = $1 AND store_id ${inHelper.clause} ${filtersSql}
    ORDER BY stock_quantity ASC, name ASC
    LIMIT $${listParams.length - 1} OFFSET $${listParams.length}
  `;
  const products = await executeDbQuery(db, listSql, listParams);

  return {
    success: true,
    statusCode: 200,
    pagination: { page: currPage, limit: currLimit, total, totalPages },
    products
  };
}

async function getInventoryMovements(db, { callerActor, storeIdFilter, productId, movementType, page, limit }) {
  const scope = await resolveAuthorizedStoreScope(db, callerActor, storeIdFilter);
  if (!scope.allowed) {
    return { success: false, statusCode: scope.statusCode, error: scope.error, message: scope.message };
  }

  const { page: currPage, limit: currLimit, offset } = parsePagination(page, limit);

  if (scope.storeIds.length === 0) {
    return {
      success: true,
      statusCode: 200,
      pagination: { page: currPage, limit: currLimit, total: 0, totalPages: 0 },
      movements: []
    };
  }

  const inHelper = buildInClause(scope.storeIds, 2);
  const queryParams = [scope.orgId, ...inHelper.params];

  let filtersSql = '';
  if (productId && typeof productId === 'string' && productId.trim()) {
    queryParams.push(productId.trim());
    filtersSql += ` AND product_id = $${queryParams.length}`;
  }
  if (movementType && typeof movementType === 'string' && movementType.trim()) {
    queryParams.push(movementType.trim().toUpperCase());
    filtersSql += ` AND movement_type = $${queryParams.length}`;
  }

  const countSql = `
    SELECT COUNT(id) AS total_count 
    FROM cloud_inventory_movements 
    WHERE org_id = $1 AND store_id ${inHelper.clause} ${filtersSql}
  `;
  const countRows = await executeDbQuery(db, countSql, queryParams);
  const total = Number(countRows[0]?.total_count) || 0;
  const totalPages = Math.ceil(total / currLimit);

  const listParams = [...queryParams, currLimit, offset];
  const listSql = `
    SELECT 
      id,
      org_id,
      store_id,
      device_id,
      movement_id_local,
      product_id,
      movement_type,
      change_quantity,
      reference_id,
      created_at
    FROM cloud_inventory_movements
    WHERE org_id = $1 AND store_id ${inHelper.clause} ${filtersSql}
    ORDER BY created_at DESC, id DESC
    LIMIT $${listParams.length - 1} OFFSET $${listParams.length}
  `;
  const movements = await executeDbQuery(db, listSql, listParams);

  return {
    success: true,
    statusCode: 200,
    pagination: { page: currPage, limit: currLimit, total, totalPages },
    movements
  };
}

// =============================================================================
// =============================================================================
// 5. IMMUTABLE ADMINISTRATIVE AUDIT TRAIL
// =============================================================================
async function getAuditLogs(db, {
  callerActor,
  actorIdFilter,
  userIdFilter,
  actionFilter,
  resourceTypeFilter,
  entityTypeFilter,
  resourceIdFilter,
  entityIdFilter,
  storeIdFilter,
  page,
  limit,
  startDate,
  from,
  endDate,
  to
}) {
  if (!callerActor || typeof callerActor !== 'object' || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED', message: 'Authentication required.' };
  }

  const role = rbac.normalizeRole(callerActor.role);
  if (!role) {
    return { success: false, statusCode: 403, error: 'INVALID_OR_UNKNOWN_ROLE', message: 'Unrecognized user role.' };
  }

  if (!rbac.hasPermission(role, rbac.PERMISSIONS.AUDIT_READ)) {
    return { success: false, statusCode: 403, error: 'FORBIDDEN', message: 'Permission audit.read required.' };
  }

  const { page: currPage, limit: currLimit, offset } = parsePagination(page, limit);
  const { orgId } = callerActor;

  let queryParams = [];
  let baseWhereSql = '';

  const effectiveStoreId = (storeIdFilter || '').trim();

  if (effectiveStoreId) {
    const accessCheck = await storeScope.validateStoreAccess(db, callerActor, effectiveStoreId);
    if (!accessCheck.allowed) {
      return { success: false, statusCode: 403, error: 'FORBIDDEN', message: 'Access to specified store audit logs denied.' };
    }
    if (role === 'PLATFORM_ADMIN') {
      queryParams.push(effectiveStoreId);
      baseWhereSql = `store_id = $1`;
    } else {
      queryParams.push(orgId, effectiveStoreId);
      baseWhereSql = `org_id = $1 AND store_id = $2`;
    }
  } else {
    if (role === 'PLATFORM_ADMIN') {
      baseWhereSql = '1=1';
    } else if (role === 'STORE_MANAGER') {
      // Store-scoped user: restrict to assigned stores
      const accessibleStores = await storeScope.getUserAccessibleStores(db, callerActor);
      const storeIds = accessibleStores.map(s => s.store_id);
      if (storeIds.length === 0) {
        return {
          success: true,
          statusCode: 200,
          pagination: { page: currPage, limit: currLimit, total: 0, totalPages: 0 },
          auditLogs: []
        };
      }
      queryParams.push(orgId);
      const inPlaceholders = storeIds.map((s, idx) => {
        queryParams.push(s);
        return `$${queryParams.length}`;
      }).join(', ');
      baseWhereSql = `org_id = $1 AND store_id IN (${inPlaceholders})`;
    } else {
      // ORG_OWNER, AUDITOR, VIEWER: organization-wide logs
      queryParams.push(orgId);
      baseWhereSql = `org_id = $1`;
    }
  }

  let filtersSql = '';
  const effectiveActorId = (actorIdFilter || userIdFilter || '').trim();
  if (effectiveActorId) {
    queryParams.push(effectiveActorId);
    filtersSql += ` AND actor_id = $${queryParams.length}`;
  }

  const effectiveAction = (actionFilter || '').trim();
  if (effectiveAction) {
    queryParams.push(effectiveAction.toUpperCase());
    filtersSql += ` AND UPPER(action) = $${queryParams.length}`;
  }

  const effectiveResourceType = (resourceTypeFilter || entityTypeFilter || '').trim();
  if (effectiveResourceType) {
    queryParams.push(effectiveResourceType.toUpperCase());
    filtersSql += ` AND UPPER(resource_type) = $${queryParams.length}`;
  }

  const effectiveResourceId = (resourceIdFilter || entityIdFilter || '').trim();
  if (effectiveResourceId) {
    queryParams.push(effectiveResourceId);
    filtersSql += ` AND resource_id = $${queryParams.length}`;
  }

  const effectiveStartDate = (startDate || from || '').trim();
  if (effectiveStartDate) {
    queryParams.push(effectiveStartDate);
    filtersSql += ` AND created_at >= $${queryParams.length}`;
  }

  const effectiveEndDate = (endDate || to || '').trim();
  if (effectiveEndDate) {
    queryParams.push(effectiveEndDate);
    filtersSql += ` AND created_at <= $${queryParams.length}`;
  }

  const countSql = `
    SELECT COUNT(id) AS total_count 
    FROM cloud_audit_logs 
    WHERE ${baseWhereSql} ${filtersSql}
  `;
  const countRows = await executeDbQuery(db, countSql, queryParams);
  const total = Number(countRows[0]?.total_count) || 0;
  const totalPages = Math.ceil(total / currLimit);

  const listParams = [...queryParams, currLimit, offset];
  const listSql = `
    SELECT 
      id,
      org_id,
      store_id,
      device_id,
      actor_id,
      actor_type,
      action,
      resource_type,
      resource_id,
      correlation_id,
      details,
      ip_address,
      user_agent,
      created_at
    FROM cloud_audit_logs
    WHERE ${baseWhereSql} ${filtersSql}
    ORDER BY created_at DESC, id DESC
    LIMIT $${listParams.length - 1} OFFSET $${listParams.length}
  `;
  const rawLogs = await executeDbQuery(db, listSql, listParams);

  // Projection Sanitization: Strictly remove any sensitive key from details
  const auditLogs = rawLogs.map(log => {
    let detailsObj = {};
    try {
      detailsObj = typeof log.details === 'string' ? JSON.parse(log.details) : (log.details || {});
    } catch {
      detailsObj = {};
    }

    delete detailsObj.password;
    delete detailsObj.newPassword;
    delete detailsObj.currentPassword;
    delete detailsObj.password_hash;
    delete detailsObj.passwordHash;
    delete detailsObj.token;
    delete detailsObj.rawToken;
    delete detailsObj.refreshToken;
    delete detailsObj.refresh_token;
    delete detailsObj.deviceKey;
    delete detailsObj.device_key;
    delete detailsObj.secret;
    delete detailsObj.apiKey;
    delete detailsObj.privateKey;

    return {
      ...log,
      details: detailsObj
    };
  });

  return {
    success: true,
    statusCode: 200,
    pagination: { page: currPage, limit: currLimit, total, totalPages },
    auditLogs
  };
}

/**
 * Fetch Single Audit Log Record by ID with strict Tenant Isolation & Sanitization
 */
async function getAuditLogById(db, { callerActor, auditId }) {
  if (!callerActor || typeof callerActor !== 'object' || !callerActor.userId) {
    return { success: false, statusCode: 401, error: 'UNAUTHENTICATED', message: 'Authentication required.' };
  }

  const role = rbac.normalizeRole(callerActor.role);
  if (!role) {
    return { success: false, statusCode: 403, error: 'INVALID_OR_UNKNOWN_ROLE', message: 'Unrecognized user role.' };
  }

  if (!rbac.hasPermission(role, rbac.PERMISSIONS.AUDIT_READ)) {
    return { success: false, statusCode: 403, error: 'FORBIDDEN', message: 'Permission audit.read required.' };
  }

  if (!auditId) {
    return { success: false, statusCode: 400, error: 'INVALID_ID', message: 'Audit log ID is required.' };
  }

  const { orgId } = callerActor;
  let querySql = '';
  let queryParams = [];

  if (role === 'PLATFORM_ADMIN') {
    querySql = `SELECT * FROM cloud_audit_logs WHERE id = $1`;
    queryParams = [auditId];
  } else {
    querySql = `SELECT * FROM cloud_audit_logs WHERE id = $1 AND org_id = $2`;
    queryParams = [auditId, orgId];
  }

  const rows = await executeDbQuery(db, querySql, queryParams);
  if (!rows || rows.length === 0) {
    return { success: false, statusCode: 404, error: 'NOT_FOUND', message: 'Audit log record not found.' };
  }

  const log = rows[0];

  // If user is store-scoped and the log is associated with a store, check access
  if (role === 'STORE_MANAGER' && log.store_id) {
    const accessCheck = await storeScope.validateStoreAccess(db, callerActor, log.store_id);
    if (!accessCheck.allowed) {
      return { success: false, statusCode: 404, error: 'NOT_FOUND', message: 'Audit log record not found.' };
    }
  }

  let detailsObj = {};
  try {
    detailsObj = typeof log.details === 'string' ? JSON.parse(log.details) : (log.details || {});
  } catch {
    detailsObj = {};
  }

  delete detailsObj.password;
  delete detailsObj.newPassword;
  delete detailsObj.currentPassword;
  delete detailsObj.password_hash;
  delete detailsObj.passwordHash;
  delete detailsObj.token;
  delete detailsObj.rawToken;
  delete detailsObj.refreshToken;
  delete detailsObj.refresh_token;
  delete detailsObj.deviceKey;
  delete detailsObj.device_key;
  delete detailsObj.secret;
  delete detailsObj.apiKey;
  delete detailsObj.privateKey;

  return {
    success: true,
    statusCode: 200,
    auditLog: {
      ...log,
      details: detailsObj
    }
  };
}

module.exports = {
  executeDbQuery,
  parsePagination,
  resolveAuthorizedStoreScope,
  getAnalyticsOverview,
  getInvoiceAnalytics,
  getInvoiceDetails,
  getShiftAnalytics,
  getShiftDetails,
  getInventoryOverview,
  getInventoryMovements,
  getAuditLogs,
  getAuditLogById
};
