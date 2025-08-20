// index.js (CommonJS)
require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');

const app = express();
app.use(express.json());

// Log every incoming request (method + path)
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

let cachedBearer = null;
let bearerExp = 0;

async function getBearer() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedBearer && bearerExp - 60 > now) return cachedBearer;

  const resp = await fetch('https://identity.filevine.com/connect/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'personal_access_token',
      token: process.env.FV_PAT,
      scope: 'fv.api.gateway.access tenant filevine.v2.api.* openid email fv.auth.tenant.read',
      client_id: process.env.FV_CLIENT_ID,
      client_secret: process.env.FV_CLIENT_SECRET
    })
  });

  const data = await resp.json();
  if (!resp.ok) throw new Error(`Token exchange failed: ${resp.status} ${JSON.stringify(data)}`);

  cachedBearer = data.access_token;
  bearerExp = Math.floor(Date.now() / 1000) + (data.expires_in || 3600);
  return cachedBearer;
}

// simple auth
app.use((req, res, next) => {
  if (req.headers['x-connector-key'] !== process.env.CONNECTOR_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

// whitelist allowed Filevine path prefixes
const ALLOW = [
  /^\/fv-app\/v2\/projects/i,
  /^\/fv-app\/v2\/documents/i,
  /^\/fv-app\/v2\/billing/i,
  /^\/fv-app\/v2\/Notes/i,
  /^\/fv-app\/v2\/contacts/i
];

// single proxy endpoint
app.post('/fv', async (req, res) => {
  try {
    const { method, targetPath, query, body } = req.body || {};
    if (!method || !targetPath) return res.status(400).json({ error: 'method and targetPath required' });
    if (!ALLOW.some(rx => rx.test(targetPath))) return res.status(403).json({ error: 'path not allowed' });

    const qs = query ? ('?' + new URLSearchParams(query).toString()) : '';
    const url = `${process.env.FV_API_BASE}${targetPath}${qs}`;
    const bearer = await getBearer();

    const upstream = await fetch(url, {
      method,
      headers: {
        'authorization': `Bearer ${bearer}`,
        'x-fv-orgid': process.env.FV_ORG_ID,
        'x-fv-userid': process.env.FV_USER_ID,
        'content-type': 'application/json'
      },
      body: ['POST','PATCH','PUT','DELETE'].includes(String(method).toUpperCase())
        ? JSON.stringify(body || {})
        : undefined
    });

    const text = await upstream.text();
    try {
      res.status(upstream.status).json(JSON.parse(text));
    } catch {
      res.status(upstream.status).json({ raw: text });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/', (_req, res) => res.send('Filevine connector is running'));
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Connector listening on :${port}`));
