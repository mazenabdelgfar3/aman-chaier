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

// In-memory cache + Global store
let memoryStore = [];

async function getLicensesList() {
  if (process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY) {
    try {
      const res = await fetch(`${process.env.SUPABASE_URL}/rest/v1/licenses?select=*`, {
        headers: {
          'apikey': process.env.SUPABASE_ANON_KEY,
          'Authorization': `Bearer ${process.env.SUPABASE_ANON_KEY}`
        }
      });
      if (res.ok) return await res.json();
    } catch (e) {}
  }
  return memoryStore;
}

async function saveLicensesList(list) {
  memoryStore = list;
  if (process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY) {
    try {
      await fetch(`${process.env.SUPABASE_URL}/rest/v1/licenses`, {
        method: 'POST',
        headers: {
          'apikey': process.env.SUPABASE_ANON_KEY,
          'Authorization': `Bearer ${process.env.SUPABASE_ANON_KEY}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates'
        },
        body: JSON.stringify(list)
      });
    } catch (e) {}
  }
}

function issueLicense(machineId, storeName, expiryDate = 'PERMANENT', phone = '', notes = '') {
  const privateKey = getPrivateKey();
  const payload = {
    machineId: machineId.trim().toUpperCase(),
    storeName: storeName.trim(),
    expiryDate,
    issuedAt: new Date().toISOString(),
  };

  const signer = crypto.createSign('sha256');
  signer.update(JSON.stringify(payload));
  const signature = signer.sign(privateKey, 'hex');

  const licenseObject = { data: payload, signature };
  const newEntry = {
    id: 'LIC-' + Date.now().toString(36).toUpperCase(),
    machineId: payload.machineId,
    storeName: payload.storeName,
    expiryDate: payload.expiryDate,
    issuedAt: payload.issuedAt,
    phone: phone.trim(),
    notes: notes.trim(),
    licenseData: licenseObject,
  };

  return { newEntry, licenseObject, licenseString: JSON.stringify(licenseObject, null, 2) };
}

// Vercel Serverless Function Handler
module.exports = async (req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // 1. GET /api/history
  if (pathname === '/api/history' && req.method === 'GET') {
    const list = await getLicensesList();
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(list));
    return;
  }

  // 2. DELETE /api/history/:id
  if (pathname.startsWith('/api/history/') && req.method === 'DELETE') {
    const id = pathname.replace('/api/history/', '');
    let list = await getLicensesList();
    list = list.filter(item => item.id !== id && item.machineId !== id);
    await saveLicensesList(list);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // 3. POST /api/issue
  if (pathname === '/api/issue' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { machineId, storeName, expiryDate, phone, notes } = JSON.parse(body || '{}');
        if (!machineId || !storeName) {
          res.statusCode = 400;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ error: 'برجاء إدخال كود الجهاز واسم المحل' }));
          return;
        }

        const { newEntry, licenseString } = issueLicense(machineId, storeName, expiryDate, phone, notes);
        const list = await getLicensesList();
        const existingIdx = list.findIndex(h => h.machineId === newEntry.machineId);
        if (existingIdx >= 0) {
          list[existingIdx] = newEntry;
        } else {
          list.unshift(newEntry);
        }

        await saveLicensesList(list);
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ success: true, entry: newEntry, licenseJson: licenseString }));
      } catch (err) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // 4. GET /api/check-license
  if (pathname === '/api/check-license') {
    const machineId = url.searchParams.get('machineId');
    const list = await getLicensesList();
    const item = list.find(h => h.machineId && machineId && h.machineId.toUpperCase() === machineId.toUpperCase());

    if (!item || !item.licenseData) {
      res.statusCode = 404;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ found: false, error: 'الترخيص غير موجود أو تم حذفه من السيرفر' }));
      return;
    }

    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({
      found: true,
      licenseData: item.licenseData,
      storeName: item.storeName,
      expiryDate: item.expiryDate
    }));
    return;
  }

  // 5. GET /api/download
  if (pathname === '/api/download') {
    const machineId = url.searchParams.get('machineId');
    const list = await getLicensesList();
    const item = list.find(h => h.machineId === machineId);

    if (!item) {
      res.statusCode = 404;
      res.end('الترخيص غير موجود');
      return;
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="license.key"');
    res.end(JSON.stringify(item.licenseData, null, 2));
    return;
  }

  res.statusCode = 404;
  res.end('Not Found');
};
