const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PRIVATE_KEY_PATH = path.join(__dirname, '../keys/private_key.pem');

function getPrivateKey() {
  if (process.env.RSA_PRIVATE_KEY) {
    return process.env.RSA_PRIVATE_KEY.replace(/\\n/g, '\n');
  }
  if (fs.existsSync(PRIVATE_KEY_PATH)) {
    return fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
  }
  return `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDWFAybARk4QFal
wuZesdnPWNH5QM9j+84HYoL1sz1VwIwcAXwvU54dEg5Xcqu73sCjQOrUmJFw6K1N
mdpvajKaChFiGEQ/hOgpIamYE5fy8gb6cM/1xZEGsna6OZ5qv4NHEJ0cSUtNI1cf
sDge1ARnOwpaFUdstGpWXX2HeD6kgJbZx3eSx9cbH+kOMgGwQYYanyzguvh7SZY+
1sh7jvGjR1akBKwqlAX6eIE4+8KI9mL1xhvs+aQ0P8gD8bOr+dDOoWU38stIf4Sk
Z4H4QwaX9tFRWdTJdkU+B3UBqBMFNnzZ1G5i+QXliwjsFUbcMWKRuH8pbH9artyp
uM/GWa4PAgMBAAECggEAZ7co8EPU+xq4n/BP+drCgqEugUqz72XESHGirvTap1v0
xXC2wJsLRFxGFHna19cwjydZXgxYklI3/Buo50eVImn0SAknr3ptm9fSOXpsqGg3
l0fmiNTh0VPPD6PwqxkDuf9Djru3vrR7dj/CwLTJOVYySrh6dSDnT9ZVhbds6fb7
pTJLqAyUSrCkBRFj29re3tbzqBc+VUH7PUjpBOp+SLeos7WsX0TtrWVSG70sTEU6
6nVkjWQyanvpaiPs91hN6pXEMajEJcepNNMfOtwM7cG6VV34fJANrgw4mkdrR6hl
ivNTu6WgWM+A2I4vOLEAy/meZklMNERh+3WqO+hdsQKBgQDyZMem/5MQKsnKuLka
FI2w6O3dnng9x+WMqCGiNgII2ArfbgGnA566C2FZ4V+pKSdk9xVgylP4pcgob4H+
xwr8hEZAw3pnwRIkwhUeaa87EwNHuTRb+mrj4vEG1LIFZJc+bGQRfsZVxxnF082h
LNVDLfM9Jw6A3N0MynHLsKAqxwKBgQDiGGABIEUZ9Wqdxp8XJvbaPFQsRCXtAAha
IBAu9OcdGF1j+GbBauaEntV+pzPtoVzIL8o5rHculB3aiL4dqtjGi1xBwGOrSoG5
mjCfKCdzGttElacMooBkknBp0VYE/dqmA8ccxtazQoY+fZRyU4wyYK3dZSVuF2LF
HBTT8AjaeQKBgHfPzMgFCCIzpC7qA8SaaDcLy5eB3xlal2JhMM7HN1Y7w5QRAgwV
w/1d5q7QscIhr3E+mHiRSdRbzYX/KBhRNmL+1uLoPLbQPjGhJWM1BgKDMVngd7sH
GpKt+ElSFPSJdiDK3uOu8EYx9dFNEhUa3gcozVRq28ZiZXkPEBSIp4K9AoGAf/r+
NQT4OIZz0FWC7k8PAl+N4fS9ZxdSovltT7cvL4gALTuJpsiFLeLexK+OtF9XrrVm
ihj26bXL5EztGMwBovl1wn5NrMMjBVWjWiQXmI9GON9hTMSbWtKNsUheobq0Tq7q
wX5IP/ZTGQJqygBC5q1VHXJIqrWwIhUQMRu5VzkCgYB1b5NzEXsnTKcX4etHNCQ9
JMwwCQQb0TkVAyVW98H913TR/uUcwZdhQnkey6PAWflgAEpWx8/cGjevHQwYOC+o
DX4GdvVv09tdXmVnIAHirwa+3e34TdaIVHexO3Y281ILsqhb1SnCkyNRz4miwWLm
htCTVjaJmmDyDmodMGSlnw==
-----END PRIVATE KEY-----`;
}

// In-memory store
let memoryStore = [];
let auditStore = [];

function signPayload(payload) {
  const privateKey = getPrivateKey();
  const signer = crypto.createSign('sha256');
  signer.update(JSON.stringify(payload));
  return signer.sign(privateKey, 'hex');
}

function logServerAudit(action, machineId, storeName, details, ip) {
  const entry = {
    id: 'AUD-' + Date.now().toString(36) + '-' + Math.random().toString(36).substring(2, 5),
    timestamp: new Date().toISOString(),
    action,
    machineId,
    storeName,
    details,
    ip: ip || 'unknown',
  };
  auditStore.unshift(entry);
  if (auditStore.length > 200) auditStore.pop();
}

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;
  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '';

  try {
    // 1. GET /api/history
    if (pathname === '/api/history' && req.method === 'GET') {
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
      return res.status(200).json(auditStore);
    }

    // 4. GET /api/check-license?machineId=XXX
    if (pathname === '/api/check-license' && req.method === 'GET') {
      const machineId = (url.searchParams.get('machineId') || '').trim().toUpperCase();
      if (!machineId) {
        return res.status(400).json({ found: false, error: 'machineId required' });
      }

      const entry = memoryStore.find(e => e.machineId.toUpperCase() === machineId);
      if (!entry) {
        return res.status(404).json({ found: false, error: 'الترخيص غير موجود أو تم حذفه من السيرفر' });
      }

      if (entry.status === 'REVOKED') {
        return res.status(200).json({
          found: true,
          revoked: true,
          status: 'REVOKED',
          message: 'تم إلغاء ترخيص هذا الجهاز'
        });
      }

      entry.lastCheckAt = new Date().toISOString();
      entry.lastIp = ip;

      return res.status(200).json({
        found: true,
        licenseData: entry.licenseData,
        storeName: entry.storeName,
        expiryDate: entry.expiryDate,
        status: entry.status || 'ACTIVE'
      });
    }

    // 5. POST /api/issue
    if (pathname === '/api/issue' && req.method === 'POST') {
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

          // فحص هل الجهاز مسجل مسبقاً -> تحديث
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

    // 7. POST /api/revoke
    if (pathname === '/api/revoke' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const { id } = JSON.parse(body);
          const entry = memoryStore.find(e => e.id === id);
          if (!entry) return res.status(404).json({ success: false, error: 'License not found' });

          entry.status = 'REVOKED';
          logServerAudit('REVOKE_LICENSE', entry.machineId, entry.storeName, 'إلغاء الترخيص', ip);

          return res.status(200).json({ success: true, entry });
        } catch (e) {
          return res.status(500).json({ success: false, error: e.message });
        }
      });
      return;
    }

    // 8. POST /api/reactivate
    if (pathname === '/api/reactivate' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const { id } = JSON.parse(body);
          const entry = memoryStore.find(e => e.id === id);
          if (!entry) return res.status(404).json({ success: false, error: 'License not found' });

          entry.status = 'ACTIVE';
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
      const id = pathname.replace('/api/delete/', '');
      const idx = memoryStore.findIndex(e => e.id === id);
      if (idx >= 0) {
        const removed = memoryStore.splice(idx, 1)[0];
        logServerAudit('DELETE_LICENSE', removed.machineId, removed.storeName, 'حذف الترخيص نهائياً', ip);
        return res.status(200).json({ success: true });
      }
      return res.status(404).json({ success: false, error: 'Not found' });
    }

    return res.status(404).json({ error: 'Endpoint not found' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};