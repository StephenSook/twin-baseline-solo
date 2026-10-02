'use strict';
// Pocketful stage 1: payments, requests, splits, activity feed and atomic settlements.
// Single-process, in-memory store. Every state mutation runs synchronously on the
// event loop, so each operation is atomic with respect to all concurrent requests.

const http = require('http');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '8080', 10);
const MAX_AMOUNT = 1000000000;
const MAX_NOTE = 200;
const HANDLE_RE = /^[a-z0-9_]{1,20}$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+$/;
const DIGITS_RE = /^[0-9]+$/;
const REQUEST_STATUSES = ['pending', 'paid', 'declined', 'cancelled'];
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

// ---------------------------------------------------------------- errors

class ApiError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}
const bad = (code, msg) => new ApiError(400, code, msg);
const invalid = (msg) => new ApiError(422, 'validation_failed', msg);
const notFound = (msg) => new ApiError(404, 'not_found', msg || 'not found');
const forbidden = (msg) => new ApiError(403, 'forbidden', msg || 'forbidden');
const conflict = (code, msg) => new ApiError(409, code, msg);

// ---------------------------------------------------------------- helpers

function nowTs() { return Math.floor(Date.now() / 1000) * 1000; }
function rfc3339(ts) {
  return new Date(ts).toISOString().replace(/\.\d{3}Z$/, '+00:00');
}
function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function charLen(s) { let n = 0; for (const _ of s) n++; return n; } // code points
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (isObj(v)) {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}
function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }

function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    const s = salt || crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, s, 32, SCRYPT, (err, key) => {
      if (err) reject(err); else resolve(`scrypt$${SCRYPT.N}$${s}$${key.toString('hex')}`);
    });
  });
}
function verifyPassword(password, stored) {
  return new Promise((resolve) => {
    const parts = typeof stored === 'string' ? stored.split('$') : [];
    if (parts.length !== 4 || parts[0] !== 'scrypt') return resolve(false);
    const N = parseInt(parts[1], 10);
    const expected = Buffer.from(parts[3], 'hex');
    crypto.scrypt(password, parts[2], expected.length || 32, { ...SCRYPT, N }, (err, key) => {
      if (err || key.length !== expected.length) return resolve(false);
      resolve(crypto.timingSafeEqual(key, expected));
    });
  });
}
// Seed passwords repeat across resets; memoize their hash so large resets stay fast.
const seedHashCache = new Map();
async function seedHash(password) {
  let h = seedHashCache.get(password);
  if (!h) {
    h = hashPassword(password);
    seedHashCache.set(password, h);
    if (seedHashCache.size > 10000) seedHashCache.clear();
  }
  return h;
}

// Validation of shared money fields ---------------------------------------

function checkAmount(body, { required = true } = {}) {
  if (!has(body, 'amount')) {
    if (required) throw invalid('amount is required');
    return undefined;
  }
  const a = body.amount;
  if (typeof a !== 'number' || !Number.isInteger(a)) throw invalid('amount must be an integer');
  if (a < 1 || a > MAX_AMOUNT) throw invalid('amount out of range');
  return a;
}
function checkNote(body) {
  if (!has(body, 'note')) return '';
  const n = body.note;
  if (typeof n !== 'string') throw invalid('note must be a string');
  if (charLen(n) > MAX_NOTE) throw invalid('note too long');
  return n;
}
function checkVisibility(body) {
  if (!has(body, 'visibility')) return 'public';
  const v = body.visibility;
  if (v !== 'public' && v !== 'private') throw invalid('visibility must be public or private');
  return v;
}
function requireString(body, field) {
  if (!has(body, field) || body[field] === undefined) throw invalid(`${field} is required`);
  if (typeof body[field] !== 'string') throw bad('malformed_request', `${field} must be a string`);
  return body[field];
}

// ---------------------------------------------------------------- state

function emptyState() {
  return {
    currency: 'EUR',
    minor_units: 2,
    seq: 0,
    counter: 0,
    users: {},          // id -> user
    emails: {},         // lowercased email -> id
    handles: {},        // handle -> id
    tokens: {},         // token -> user id
    payments: {},       // id -> payment record
    paymentOrder: [],   // ids in creation order
    requests: {},       // id -> request record
    requestOrder: [],
    splits: {},
    settlements: {},
    operators: [],
    idem: {},           // scope key -> { canon, response }
  };
}
let S = emptyState();

function nextSeq() { return ++S.seq; }
function newId(prefix, table) {
  let id;
  do { id = `${prefix}${(++S.counter).toString(36)}`; } while (table[id]);
  return id;
}

function paymentView(p) {
  const from = S.users[p.from_user_id];
  const to = S.users[p.to_user_id];
  return {
    payment_id: p.id,
    from_user_id: p.from_user_id,
    from_handle: from ? from.handle : null,
    to_user_id: p.to_user_id,
    to_handle: to ? to.handle : null,
    amount: p.amount,
    currency: S.currency,
    note: p.note,
    visibility: p.visibility,
    request_id: p.request_id,
    settlement_id: p.settlement_id,
    created_at: p.created_at,
  };
}
function requestView(r) {
  const rq = S.users[r.requester_id];
  const py = S.users[r.payer_id];
  return {
    request_id: r.id,
    requester_id: r.requester_id,
    requester_handle: rq ? rq.handle : null,
    payer_id: r.payer_id,
    payer_handle: py ? py.handle : null,
    amount: r.amount,
    currency: S.currency,
    note: r.note,
    status: r.status,
    payment_id: r.payment_id,
    created_at: r.created_at,
  };
}
function meView(u) {
  return {
    user_id: u.id, display_name: u.display_name, handle: u.handle, email: u.email,
    balance: u.balance, currency: S.currency, minor_units: S.minor_units,
  };
}

function insertPayment(p) {
  S.payments[p.id] = p;
  S.paymentOrder.push(p.id);
}
function newestFirst(a, b) { return (b.ts - a.ts) || (b.seq - a.seq); }

// Move money between two wallets. Caller has already checked affordability.
function transfer(fromId, toId, amount) {
  S.users[fromId].balance -= amount;
  S.users[toId].balance += amount;
}

// ---------------------------------------------------------------- reset / import

function parseOptionalTs(v, fallback) {
  if (v === undefined || v === null) return fallback;
  if (typeof v !== 'string') throw invalid('created_at must be a string');
  const t = Date.parse(v);
  if (Number.isNaN(t)) throw invalid('invalid created_at');
  return t;
}

async function buildFromFixture(fx) {
  if (!isObj(fx)) throw invalid('fixture must be an object');
  const st = emptyState();
  if (typeof fx.currency !== 'string' || !fx.currency) throw invalid('currency is required');
  st.currency = fx.currency;
  if (!Number.isInteger(fx.minor_units) || ![0, 2, 3].includes(fx.minor_units)) {
    throw invalid('minor_units must be 0, 2 or 3');
  }
  st.minor_units = fx.minor_units;
  const users = fx.users === undefined ? [] : fx.users;
  const payments = fx.payments === undefined || fx.payments === null ? [] : fx.payments;
  const requests = fx.requests === undefined || fx.requests === null ? [] : fx.requests;
  const ops = fx.settlement_operator_ids === undefined || fx.settlement_operator_ids === null
    ? [] : fx.settlement_operator_ids;
  if (!Array.isArray(users) || !Array.isArray(payments) || !Array.isArray(requests) || !Array.isArray(ops)) {
    throw invalid('users, payments, requests and settlement_operator_ids must be arrays');
  }
  const base = nowTs();
  for (const u of users) {
    if (!isObj(u)) throw invalid('user must be an object');
    const { id, email, password, handle, balance } = u;
    if (typeof id !== 'string' || !id || id.length > 64) throw invalid('user id');
    if (typeof email !== 'string' || !email) throw invalid('user email');
    if (typeof password !== 'string') throw invalid('user password');
    if (typeof handle !== 'string' || !HANDLE_RE.test(handle)) throw invalid('user handle');
    if (typeof balance !== 'number' || !Number.isInteger(balance)) throw invalid('user balance');
    if (balance < 0) throw invalid('negative balance');
    if (balance > Number.MAX_SAFE_INTEGER) throw invalid('balance out of range');
    if (st.users[id]) throw invalid('duplicate user id');
    if (st.handles[handle]) throw invalid('duplicate handle');
    const ek = email.toLowerCase();
    if (st.emails[ek]) throw invalid('duplicate email');
    const display = typeof u.display_name === 'string' ? u.display_name : handle;
    st.users[id] = { id, email, handle, display_name: display, balance, pw: null, password };
    st.handles[handle] = id;
    st.emails[ek] = id;
  }
  for (const id of ops) {
    if (typeof id !== 'string' || !st.users[id]) throw invalid('unknown settlement operator');
    if (!st.operators.includes(id)) st.operators.push(id);
  }
  for (const p of payments) {
    if (!isObj(p)) throw invalid('payment must be an object');
    const id = p.id;
    if (typeof id !== 'string' || !id || id.length > 64 || st.payments[id]) throw invalid('payment id');
    if (!st.users[p.from_user_id] || !st.users[p.to_user_id]) throw invalid('payment user');
    if (typeof p.amount !== 'number' || !Number.isInteger(p.amount) || p.amount < 0) throw invalid('payment amount');
    const note = p.note === undefined ? '' : p.note;
    if (typeof note !== 'string') throw invalid('payment note');
    const vis = p.visibility === undefined ? 'public' : p.visibility;
    if (vis !== 'public' && vis !== 'private') throw invalid('payment visibility');
    const seq = ++st.seq;
    const ts = parseOptionalTs(p.created_at, base);
    st.payments[id] = {
      id, from_user_id: p.from_user_id, to_user_id: p.to_user_id, amount: p.amount, note,
      visibility: vis, request_id: typeof p.request_id === 'string' ? p.request_id : null,
      settlement_id: typeof p.settlement_id === 'string' ? p.settlement_id : null,
      created_at: typeof p.created_at === 'string' ? p.created_at : rfc3339(ts), ts, seq,
    };
    st.paymentOrder.push(id);
  }
  for (const r of requests) {
    if (!isObj(r)) throw invalid('request must be an object');
    const id = r.id;
    if (typeof id !== 'string' || !id || id.length > 64 || st.requests[id]) throw invalid('request id');
    if (!st.users[r.requester_id] || !st.users[r.payer_id]) throw invalid('request user');
    if (typeof r.amount !== 'number' || !Number.isInteger(r.amount) || r.amount < 0) throw invalid('request amount');
    const note = r.note === undefined ? '' : r.note;
    if (typeof note !== 'string') throw invalid('request note');
    const status = r.status === undefined ? 'pending' : r.status;
    if (!REQUEST_STATUSES.includes(status)) throw invalid('request status');
    const seq = ++st.seq;
    const ts = parseOptionalTs(r.created_at, base);
    st.requests[id] = {
      id, requester_id: r.requester_id, payer_id: r.payer_id, amount: r.amount, note, status,
      payment_id: typeof r.payment_id === 'string' ? r.payment_id : null,
      created_at: typeof r.created_at === 'string' ? r.created_at : rfc3339(ts), ts, seq,
    };
    st.requestOrder.push(id);
  }
  // Hash seed passwords (memoized across resets).
  const list = Object.values(st.users);
  const hashes = await Promise.all(list.map((u) => seedHash(u.password)));
  list.forEach((u, i) => { u.pw = hashes[i]; delete u.password; });
  return st;
}

function exportState() {
  return { track: 'pocketful', format_version: 1, state: JSON.parse(JSON.stringify(S)) };
}

function validateImported(st) {
  if (!isObj(st)) throw invalid('state must be an object');
  const tmpl = emptyState();
  for (const k of Object.keys(tmpl)) {
    if (!has(st, k)) throw invalid(`state.${k} missing`);
    const want = tmpl[k];
    if (Array.isArray(want) ? !Array.isArray(st[k]) : typeof want === 'object' ? !isObj(st[k]) : typeof st[k] !== typeof want) {
      throw invalid(`state.${k} has the wrong type`);
    }
  }
  if (![0, 2, 3].includes(st.minor_units)) throw invalid('minor_units');
  if (!Number.isInteger(st.seq) || !Number.isInteger(st.counter)) throw invalid('counters');
  for (const [id, u] of Object.entries(st.users)) {
    if (!isObj(u) || u.id !== id || typeof u.handle !== 'string' || typeof u.email !== 'string'
      || typeof u.pw !== 'string' || !Number.isInteger(u.balance) || u.balance < 0) {
      throw invalid('invalid user');
    }
    if (st.handles[u.handle] !== id || st.emails[u.email.toLowerCase()] !== id) throw invalid('user index');
  }
  for (const uid of Object.values(st.tokens)) if (!st.users[uid]) throw invalid('token user');
  for (const uid of st.operators) if (!st.users[uid]) throw invalid('operator user');
  for (const [id, p] of Object.entries(st.payments)) {
    if (!isObj(p) || p.id !== id || !st.users[p.from_user_id] || !st.users[p.to_user_id]
      || !Number.isInteger(p.amount) || typeof p.created_at !== 'string'
      || typeof p.ts !== 'number' || typeof p.seq !== 'number') throw invalid('invalid payment');
  }
  for (const id of st.paymentOrder) if (!st.payments[id]) throw invalid('payment order');
  if (st.paymentOrder.length !== Object.keys(st.payments).length) throw invalid('payment order');
  for (const [id, r] of Object.entries(st.requests)) {
    if (!isObj(r) || r.id !== id || !st.users[r.requester_id] || !st.users[r.payer_id]
      || !Number.isInteger(r.amount) || !REQUEST_STATUSES.includes(r.status)
      || typeof r.ts !== 'number' || typeof r.seq !== 'number') throw invalid('invalid request');
  }
  for (const id of st.requestOrder) if (!st.requests[id]) throw invalid('request order');
  if (st.requestOrder.length !== Object.keys(st.requests).length) throw invalid('request order');
  for (const rec of Object.values(st.idem)) {
    if (!isObj(rec) || typeof rec.canon !== 'string' || !isObj(rec.response)) throw invalid('idempotency record');
  }
  return st;
}

// ---------------------------------------------------------------- auth

function authenticate(req) {
  const h = req.headers.authorization;
  if (typeof h !== 'string') throw new ApiError(401, 'unauthenticated', 'missing bearer token');
  const m = /^Bearer\s+(\S+)\s*$/i.exec(h);
  if (!m) throw new ApiError(401, 'unauthenticated', 'malformed bearer token');
  const uid = has(S.tokens, m[1]) ? S.tokens[m[1]] : undefined;
  const user = uid && S.users[uid];
  if (!user) throw new ApiError(401, 'unauthenticated', 'unknown token');
  return user;
}
function issueToken(uid) {
  const t = crypto.randomBytes(24).toString('base64url');
  S.tokens[t] = uid;
  return t;
}
function deriveHandle(email) {
  const local = email.slice(0, email.lastIndexOf('@')).toLowerCase();
  let out = '';
  for (const ch of local) out += /^[a-z0-9_]$/.test(ch) ? ch : '_';
  return [...out].slice(0, 20).join('');
}

async function signup(body) {
  const email = requireString(body, 'email');
  const password = requireString(body, 'password');
  if (has(body, 'display_name') && body.display_name !== undefined && typeof body.display_name !== 'string') {
    throw bad('malformed_request', 'display_name must be a string');
  }
  if (charLen(password) < 8) throw invalid('password must be at least 8 characters');
  if (!EMAIL_RE.test(email)) throw invalid('email must look like local@domain');
  if (typeof body.display_name !== 'string') throw invalid('display_name is required');
  const display = body.display_name;
  const handle = deriveHandle(email);
  const pre = () => {
    if (S.emails[email.toLowerCase()]) throw conflict('email_taken', 'email already registered');
    if (!HANDLE_RE.test(handle) || S.handles[handle]) throw conflict('handle_taken', 'handle already taken');
  };
  pre();
  const pw = await hashPassword(password);
  pre(); // re-check after the async hash: the store may have changed meanwhile
  const id = newId('u_', S.users);
  S.users[id] = { id, email, handle, display_name: display, balance: 0, pw };
  S.emails[email.toLowerCase()] = id;
  S.handles[handle] = id;
  return [201, { user_id: id, display_name: display, handle, token: issueToken(id) }];
}

async function login(body) {
  const email = requireString(body, 'email');
  const password = requireString(body, 'password');
  const fail = () => new ApiError(401, 'unauthenticated', 'invalid email or password');
  const stateAtStart = S;
  const uid = S.emails[email.toLowerCase()];
  const user = uid && S.users[uid];
  if (!user) throw fail();
  const ok = await verifyPassword(password, user.pw);
  if (!ok || S !== stateAtStart || S.users[uid] !== user) throw fail();
  return [200, { user_id: uid, display_name: user.display_name, handle: user.handle, token: issueToken(uid) }];
}

// ---------------------------------------------------------------- idempotency

function idempotent(req, user, pathKey, raw, fn) {
  const key = req.headers['idempotency-key'];
  if (key === undefined || key === '') throw bad('missing_idempotency_key', 'Idempotency-Key header is required');
  if (key.length > 255) throw invalid('Idempotency-Key must be 1 to 255 characters');
  const body = parseObject(raw);
  const scope = `${user.id}\u0000${pathKey}\u0000${key}`;
  const canon = canonical(body);
  const rec = has(S.idem, scope) ? S.idem[scope] : undefined;
  if (rec) {
    if (rec.canon !== canon) throw conflict('idempotency_key_reuse', 'key already used with a different body');
    return [200, rec.response];
  }
  const response = fn(body);
  S.idem[scope] = { canon, response };
  return [201, response];
}

// ---------------------------------------------------------------- handlers

function lookupHandle(h) {
  const id = has(S.handles, h) ? S.handles[h] : undefined;
  if (!id) throw notFound(`no user with handle ${h}`);
  return S.users[id];
}

function createPayment(user, body) {
  const amount = checkAmount(body);
  const toHandle = requireString(body, 'to_handle');
  const note = checkNote(body);
  const visibility = checkVisibility(body);
  if (toHandle === user.handle) throw new ApiError(422, 'self_payment', 'cannot pay yourself');
  const to = lookupHandle(toHandle);
  if (user.balance < amount) throw conflict('insufficient_funds', 'insufficient funds');
  const ts = Date.now();
  const p = {
    id: newId('p_', S.payments), from_user_id: user.id, to_user_id: to.id, amount, note, visibility,
    request_id: null, settlement_id: null, created_at: rfc3339(ts), ts, seq: nextSeq(),
  };
  transfer(user.id, to.id, amount);
  insertPayment(p);
  return paymentView(p);
}

function createRequest(user, body) {
  const amount = checkAmount(body);
  const payerHandle = requireString(body, 'payer_handle');
  const note = checkNote(body);
  if (payerHandle === user.handle) throw new ApiError(422, 'self_request', 'cannot request from yourself');
  const payer = lookupHandle(payerHandle);
  return requestView(newRequest(user.id, payer.id, amount, note, Date.now()));
}
function newRequest(requesterId, payerId, amount, note, ts) {
  const r = {
    id: newId('rq_', S.requests), requester_id: requesterId, payer_id: payerId, amount, note,
    status: 'pending', payment_id: null, created_at: rfc3339(ts), ts, seq: nextSeq(),
  };
  S.requests[r.id] = r;
  S.requestOrder.push(r.id);
  return r;
}

function getRequestFor(user, id) {
  const r = has(S.requests, id) ? S.requests[id] : undefined;
  if (!r) throw notFound('no such request');
  return r;
}

function payRequest(user, id, body) {
  const visibility = checkVisibility(body);
  const r = getRequestFor(user, id);
  if (r.payer_id !== user.id) throw forbidden('only the payer may pay this request');
  if (r.status !== 'pending') throw conflict('request_not_pending', `request is ${r.status}`);
  if (user.balance < r.amount) throw conflict('insufficient_funds', 'insufficient funds');
  const ts = Date.now();
  const p = {
    id: newId('p_', S.payments), from_user_id: user.id, to_user_id: r.requester_id, amount: r.amount,
    note: r.note, visibility, request_id: r.id, settlement_id: null, created_at: rfc3339(ts), ts, seq: nextSeq(),
  };
  transfer(user.id, r.requester_id, r.amount);
  insertPayment(p);
  r.status = 'paid';
  r.payment_id = p.id;
  return paymentView(p);
}

function declineRequest(user, id) {
  const r = getRequestFor(user, id);
  if (r.payer_id !== user.id) throw forbidden('only the payer may decline this request');
  if (r.status === 'pending') r.status = 'declined';
  else if (r.status !== 'declined') throw conflict('request_not_pending', `request is ${r.status}`);
  return requestView(r);
}
function cancelRequest(user, id) {
  const r = getRequestFor(user, id);
  if (r.requester_id !== user.id) throw forbidden('only the requester may cancel this request');
  if (r.status === 'pending') r.status = 'cancelled';
  else if (r.status !== 'cancelled') throw conflict('request_not_pending', `request is ${r.status}`);
  return requestView(r);
}

function equalSplit(amount, n) {
  const base = Math.floor(amount / n);
  const rem = amount - base * n;
  const out = [];
  for (let i = 0; i < n; i++) out.push(base + (i < rem ? 1 : 0));
  return out;
}

function createSplit(user, body) {
  const amount = checkAmount(body);
  if (!has(body, 'participant_handles') || body.participant_handles === undefined) {
    throw invalid('participant_handles is required');
  }
  const handles = body.participant_handles;
  if (!Array.isArray(handles)) throw bad('malformed_request', 'participant_handles must be an array');
  for (const h of handles) if (typeof h !== 'string') throw bad('malformed_request', 'handles must be strings');
  if (handles.length === 0) throw invalid('participant_handles must not be empty');
  if (new Set(handles).size !== handles.length) throw invalid('duplicate handle');
  const note = checkNote(body);
  const users = handles.map(lookupHandle);
  const shares = equalSplit(amount, handles.length);
  const ts = Date.now();
  const requests = [];
  users.forEach((u, i) => {
    if (u.id === user.id) return;
    requests.push(requestView(newRequest(user.id, u.id, shares[i], note, ts)));
  });
  const split = {
    split_id: newId('sp_', S.splits), amount, currency: S.currency, note,
    shares: handles.map((h, i) => ({ handle: h, amount: shares[i] })),
    requests, created_at: rfc3339(ts),
  };
  S.splits[split.split_id] = { id: split.split_id, requester_id: user.id, response: split };
  return split;
}

function createSettlement(user, body) {
  const transfers = body.transfers;
  if (!Array.isArray(transfers) || transfers.length < 1 || transfers.length > 32) {
    throw invalid('transfers must contain 1 to 32 entries');
  }
  const entries = transfers.map((t, i) => {
    if (!isObj(t)) throw invalid(`transfers[${i}] must be an object`);
    const amount = checkAmount(t);
    for (const f of ['from_handle', 'to_handle']) {
      if (typeof t[f] !== 'string') throw invalid(`transfers[${i}].${f} must be a string`);
    }
    const note = checkNote(t);
    const visibility = checkVisibility(t);
    const from = lookupHandle(t.from_handle);
    const to = lookupHandle(t.to_handle);
    if (from.id === to.id) throw new ApiError(422, 'self_payment', `transfers[${i}] is a self-transfer`);
    return { from, to, amount, note, visibility };
  });
  const net = new Map();
  for (const e of entries) {
    net.set(e.from.id, (net.get(e.from.id) || 0) - e.amount);
    net.set(e.to.id, (net.get(e.to.id) || 0) + e.amount);
  }
  for (const [uid, delta] of net) {
    if (S.users[uid].balance + delta < 0) throw conflict('insufficient_funds', 'settlement is not affordable');
  }
  const ts = Date.now();
  const committed_at = rfc3339(ts);
  const settlement_id = newId('st_', S.settlements);
  const payments = entries.map((e) => {
    const p = {
      id: newId('p_', S.payments), from_user_id: e.from.id, to_user_id: e.to.id, amount: e.amount,
      note: e.note, visibility: e.visibility, request_id: null, settlement_id, created_at: committed_at,
      ts, seq: nextSeq(),
    };
    insertPayment(p);
    return p;
  });
  // Apply net deltas: every intermediate balance stays nonnegative.
  for (const [uid, delta] of net) S.users[uid].balance += delta;
  const response = { settlement_id, committed_at, payments: payments.map(paymentView) };
  S.settlements[settlement_id] = { id: settlement_id, operator_id: user.id, payment_ids: payments.map((p) => p.id), response };
  return response;
}

function pageParams(q) {
  const parse = (name, def, min, max) => {
    if (!q.has(name)) return def;
    const raw = q.get(name);
    if (!DIGITS_RE.test(raw)) throw invalid(`${name} must be a non-negative integer`);
    const n = Number(raw);
    if (n < min || (max !== undefined && n > max)) throw invalid(`${name} out of range`);
    return n;
  };
  return { limit: parse('limit', 50, 1, 200), offset: parse('offset', 0, 0) };
}

function listActivity(user, q) {
  const { limit, offset } = pageParams(q);
  const items = Object.values(S.payments)
    .filter((p) => p.visibility === 'public' || p.from_user_id === user.id || p.to_user_id === user.id)
    .sort(newestFirst);
  const page = items.slice(offset, offset + limit);
  return { payments: page.map(paymentView), has_more: offset + page.length < items.length };
}

function listRequests(user, q) {
  const { limit, offset } = pageParams(q);
  let direction = null;
  if (q.has('direction')) {
    direction = q.get('direction');
    if (direction !== 'incoming' && direction !== 'outgoing') throw invalid('direction must be incoming or outgoing');
  }
  let status = null;
  if (q.has('status')) {
    status = q.get('status');
    if (!REQUEST_STATUSES.includes(status)) throw invalid('unknown status');
  }
  const items = Object.values(S.requests).filter((r) => {
    const incoming = r.payer_id === user.id;
    const outgoing = r.requester_id === user.id;
    if (direction === 'incoming' ? !incoming : direction === 'outgoing' ? !outgoing : !(incoming || outgoing)) return false;
    return status === null || r.status === status;
  }).sort(newestFirst);
  const page = items.slice(offset, offset + limit);
  return { requests: page.map(requestView), has_more: offset + page.length < items.length };
}

// ---------------------------------------------------------------- HTTP plumbing

function send(res, status, body) {
  if (status === 204) {
    res.writeHead(204);
    res.end();
    return;
  }
  const data = Buffer.from(JSON.stringify(body), 'utf8');
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': data.length });
  res.end(data);
}
function sendError(res, err) {
  send(res, err.status, { error: { code: err.code, message: err.message || err.code } });
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooBig = false;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) tooBig = true; else chunks.push(c);
    });
    req.on('end', () => (tooBig ? reject(new ApiError(413, 'payload_too_large', 'request body too large'))
      : resolve(Buffer.concat(chunks).toString('utf8'))));
    req.on('error', reject);
  });
}
function parseJson(raw, { emptyAs = {} } = {}) {
  if (raw.trim() === '') return emptyAs;
  try {
    return JSON.parse(raw);
  } catch (e) {
    throw bad('malformed_request', 'body is not valid JSON');
  }
}
function parseObject(raw) {
  const v = parseJson(raw);
  if (!isObj(v)) throw bad('malformed_request', 'body must be a JSON object');
  return v;
}

let resetChain = Promise.resolve();
function serialized(fn) {
  const run = resetChain.then(fn, fn);
  resetChain = run.catch(() => {});
  return run;
}

async function route(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, '') : url.pathname;
  const q = url.searchParams;
  const method = req.method;
  const isTest = path.startsWith('/_test/');
  const raw = method === 'GET' || method === 'HEAD' ? '' : await readBody(req, isTest ? 256 * 1024 * 1024 : 1024 * 1024);

  if (path === '/health') {
    if (method !== 'GET') throw new ApiError(405, 'method_not_allowed', 'method not allowed');
    return [200, { status: 'ok' }];
  }
  if (path === '/_test/reset' && method === 'POST') {
    const fx = parseJson(raw, { emptyAs: null });
    return serialized(async () => {
      const st = await buildFromFixture(fx);
      S = st;
      return [204, null];
    });
  }
  if (path === '/_test/export' && method === 'GET') return [200, exportState()];
  if (path === '/_test/import' && method === 'POST') {
    const doc = parseJson(raw, { emptyAs: null });
    return serialized(async () => {
      if (!isObj(doc)) throw invalid('import body must be an object');
      if (doc.track !== 'pocketful') throw invalid('wrong track');
      if (doc.format_version !== 1) throw invalid('wrong format_version');
      if (!has(doc, 'state')) throw invalid('state is required');
      const st = validateImported(JSON.parse(JSON.stringify(doc.state)));
      S = st;
      return [204, null];
    });
  }
  if (path === '/auth/signup' && method === 'POST') return signup(parseObject(raw));
  if (path === '/auth/login' && method === 'POST') return login(parseObject(raw));

  const parts = path.split('/').filter(Boolean).map(decodeURIComponent);
  const known = ['me', 'payments', 'requests', 'splits', 'activity', 'settlements'];
  if (!known.includes(parts[0])) throw notFound('no such route');
  const user = authenticate(req);

  if (parts.length === 1) {
    switch (`${method} ${parts[0]}`) {
      case 'GET me': return [200, meView(user)];
      case 'GET activity': return [200, listActivity(user, q)];
      case 'GET requests': return [200, listRequests(user, q)];
      case 'POST payments': return idempotent(req, user, 'POST /payments', raw, (b) => createPayment(user, b));
      case 'POST requests': return idempotent(req, user, 'POST /requests', raw, (b) => createRequest(user, b));
      case 'POST splits': return idempotent(req, user, 'POST /splits', raw, (b) => createSplit(user, b));
      case 'POST settlements':
        if (!S.operators.includes(user.id)) throw forbidden('settlement operator required');
        return idempotent(req, user, 'POST /settlements', raw, (b) => createSettlement(user, b));
      default: break;
    }
  }
  if (parts.length === 2 && method === 'GET') {
    const id = parts[1];
    if (parts[0] === 'payments') {
      const p = has(S.payments, id) ? S.payments[id] : undefined;
      if (!p || !(p.visibility === 'public' || p.from_user_id === user.id || p.to_user_id === user.id)) throw notFound('no such payment');
      return [200, paymentView(p)];
    }
    if (parts[0] === 'requests') {
      const r = has(S.requests, id) ? S.requests[id] : undefined;
      if (!r || (r.payer_id !== user.id && r.requester_id !== user.id)) throw notFound('no such request');
      return [200, requestView(r)];
    }
    if (parts[0] === 'settlements') {
      const s = has(S.settlements, id) ? S.settlements[id] : undefined;
      if (!s || !S.operators.includes(user.id)) throw notFound('no such settlement');
      return [200, { settlement_id: s.id, committed_at: s.response.committed_at, payments: s.payment_ids.map((pid) => paymentView(S.payments[pid])) }];
    }
  }
  if (parts.length === 3 && parts[0] === 'requests' && method === 'POST') {
    const id = parts[1];
    if (parts[2] === 'pay') {
      return idempotent(req, user, `POST /requests/${id}/pay`, raw, (b) => payRequest(user, id, b));
    }
    if (parts[2] === 'decline') { parseObject(raw); return [200, declineRequest(user, id)]; }
    if (parts[2] === 'cancel') { parseObject(raw); return [200, cancelRequest(user, id)]; }
  }
  throw notFound('no such route');
}

const server = http.createServer(async (req, res) => {
  try {
    const [status, body] = await route(req, res);
    send(res, status, body);
  } catch (err) {
    if (err instanceof ApiError) {
      sendError(res, err);
    } else if (err instanceof URIError) {
      sendError(res, notFound('bad path'));
    } else {
      console.error(err);
      sendError(res, new ApiError(500, 'internal_error', 'internal error'));
    }
  }
});
server.keepAliveTimeout = 65000;
server.listen(PORT, '0.0.0.0', () => console.log(`pocketful listening on ${PORT}`));
