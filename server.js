import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const { CANVA_CLIENT_ID, CANVA_CLIENT_SECRET, BASE_URL = 'http://127.0.0.1:3001', PORT = 3001 } = process.env;
const REDIRECT = `${BASE_URL}/oauth/redirect`;
const API = 'https://api.canva.com/rest/v1';
const TOKEN_FILE = './tokens.json';
const THUMB_DIR = './public/thumbs';
const basic = Buffer.from(`${CANVA_CLIENT_ID}:${CANVA_CLIENT_SECRET}`).toString('base64');

const app = express();
app.use(express.static('public'));
await fs.mkdir(THUMB_DIR, { recursive: true });

let pending = {}; // state -> code_verifier (cukup untuk 1 pemilik akun)
const b64url = (b) => b.toString('base64url');

// ---------- 1. Login OAuth (PKCE), cukup dilakukan sekali ----------
app.get('/login', (req, res) => {
  const verifier = b64url(crypto.randomBytes(48));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(16));
  pending[state] = verifier;
  const url = new URL('https://www.canva.com/api/oauth/authorize');
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: CANVA_CLIENT_ID,
    redirect_uri: REDIRECT,
    scope: 'design:meta:read',
    code_challenge: challenge,
    code_challenge_method: 's256',
    state,
  });
  res.redirect(url.toString());
});

app.get('/oauth/redirect', async (req, res) => {
  const { code, state } = req.query;
  const verifier = pending[state];
  if (!code || !verifier) return res.status(400).send('State/code tidak valid');
  delete pending[state];
  await tokenRequest({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT });
  res.redirect('/');
});

async function tokenRequest(params) {
  const r = await fetch(`${API}/oauth/token`, {
    method: 'POST',
    headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params),
  });
  if (!r.ok) throw new Error(`Token error ${r.status}: ${await r.text()}`);
  const t = await r.json();
  t.expires_at = Date.now() + (t.expires_in - 60) * 1000;
  await fs.writeFile(TOKEN_FILE, JSON.stringify(t));
  return t;
}

async function accessToken() {
  let t;
  try { t = JSON.parse(await fs.readFile(TOKEN_FILE, 'utf8')); } catch { return null; }
  if (Date.now() < t.expires_at) return t.access_token;
  // refresh token sekali pakai: token baru dari respons wajib disimpan (sudah di tokenRequest)
  t = await tokenRequest({ grant_type: 'refresh_token', refresh_token: t.refresh_token });
  return t.access_token;
}

// ---------- 2. Ambil semua desain + unduh thumbnail ----------
let cache = { at: 0, data: [] };

async function fetchAllDesigns(token) {
  const items = [];
  let continuation;
  do {
    const u = new URL(`${API}/designs`);
    u.searchParams.set('ownership', 'owned');
    u.searchParams.set('sort_by', 'modified_descending');
    u.searchParams.set('limit', '50');
    if (continuation) u.searchParams.set('continuation', continuation);
    const r = await fetch(u, { headers: { Authorization: `Bearer ${token}` } });
    if (!r.ok) throw new Error(`List designs ${r.status}: ${await r.text()}`);
    const j = await r.json();
    items.push(...j.items);
    continuation = j.continuation;
  } while (continuation);
  return items;
}

async function saveThumb(d) {
  if (!d.thumbnail?.url) return null;
  const base = `${d.id}-${d.updated_at}`;
  for (const ext of ['png', 'jpg']) {
    try { await fs.access(path.join(THUMB_DIR, `${base}.${ext}`)); return `/thumbs/${base}.${ext}`; } catch {}
  }
  // URL thumbnail kedaluwarsa cepat, jadi langsung diunduh & disimpan sendiri
  const r = await fetch(d.thumbnail.url);
  if (!r.ok) return null;
  const ext = (r.headers.get('content-type') || '').includes('png') ? 'png' : 'jpg';
  await fs.writeFile(path.join(THUMB_DIR, `${base}.${ext}`), Buffer.from(await r.arrayBuffer()));
  return `/thumbs/${base}.${ext}`;
}

app.get('/api/designs', async (req, res) => {
  try {
    if (Date.now() - cache.at < 5 * 60 * 1000) return res.json(cache.data); // cache 5 menit
    const token = await accessToken();
    if (!token) return res.status(401).json({ error: 'belum login', login: '/login' });
    const items = await fetchAllDesigns(token);
    const data = await Promise.all(items.map(async (d) => ({
      id: d.id,
      title: d.title || '',
      thumb: await saveThumb(d),
      view: d.urls.view_url,   // URL ini juga sementara: tombol Lihat/Edit sebaiknya lewat /go/:id
      edit: d.urls.edit_url,
      pages: d.page_count,
      updated: d.updated_at,
    })));
    cache = { at: Date.now(), data };
    res.json(data);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`Buka ${BASE_URL}  (login pertama kali: ${BASE_URL}/login)`));
