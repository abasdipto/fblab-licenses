// CI license signer. Reads inputs from env (set by GH Actions).
// Reads private.pem from repo root (written by workflow from secret).
// Updates licenses.json in repo root.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PRIVATE_KEY_PATH = path.join(__dirname, 'private.pem');
const LICENSES_PATH = path.join(__dirname, 'licenses.json');

function loadPayload() {
    if (!fs.existsSync(LICENSES_PATH)) return { version: 1, licenses: [] };
    try {
        const doc = JSON.parse(fs.readFileSync(LICENSES_PATH, 'utf8'));
        if (doc.payload) return JSON.parse(doc.payload);
        return doc;
    } catch { return { version: 1, licenses: [] }; }
}

function sign(payload) {
    const privKey = fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
    const payloadStr = JSON.stringify(payload);
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(payloadStr);
    signer.end();
    const signature = signer.sign(privKey, 'base64');
    return { payload: payloadStr, signature, generatedAt: new Date().toISOString() };
}

function save(payload) {
    const doc = sign(payload);
    fs.writeFileSync(LICENSES_PATH, JSON.stringify(doc, null, 2));
    console.log(`Wrote ${LICENSES_PATH} with ${payload.licenses.length} license(s).`);
}

const action = (process.env.ACTION || 'add').toLowerCase();
const key = (process.env.KEY || '').trim().toUpperCase();
const hwid = (process.env.HWID || '').trim();
const days = Number(process.env.DAYS) || 365;
const note = (process.env.NOTE || '').trim();

if (!key) { console.error('ERROR: KEY required'); process.exit(1); }

const payload = loadPayload();

if (action === 'add') {
    if (!hwid) { console.error('ERROR: HWID required for add'); process.exit(1); }
    if (payload.licenses.find(l => l.key === key)) {
        console.error(`ERROR: Key ${key} already exists. Revoke first.`);
        process.exit(1);
    }
    const expires = days > 0 ? new Date(Date.now() + days * 86400 * 1000).toISOString() : null;
    payload.licenses.push({
        key, hwid, expires, revoked: false, note,
        addedAt: new Date().toISOString()
    });
    save(payload);
    console.log(`ADDED: ${key} → HWID ${hwid.slice(0,8)}... expires ${expires || 'never'} note="${note}"`);
} else if (action === 'revoke') {
    const entry = payload.licenses.find(l => l.key === key);
    if (!entry) { console.error(`ERROR: Key ${key} not found`); process.exit(1); }
    entry.revoked = true;
    entry.revokedAt = new Date().toISOString();
    save(payload);
    console.log(`REVOKED: ${key}`);
} else {
    console.error(`ERROR: unknown action "${action}". Use add or revoke.`);
    process.exit(1);
}
