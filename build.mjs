#!/usr/bin/env node
// Mat Strong build: encrypts content/content.json into src/template.html -> index.html
// Usage: node build.mjs "<password>"
// The repo is public; only the encrypted payload ships. Plaintext stays in content/ (gitignored).
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';

const ITER = 600_000;
// Password: argv override (rotation), else read from gitignored docs/DEPLOY.md —
// keeps the secret off the command line, out of `ps`, and out of session logs.
let password = process.argv[2];
if (!password) {
  try {
    const deploy = readFileSync(new URL('./docs/DEPLOY.md', import.meta.url), 'utf8');
    password = (deploy.match(/Password: `([^`]+)`/) || [])[1];
  } catch { /* fall through to usage error */ }
}
if (!password || password.length < 8) {
  console.error('Usage: node build.mjs ["<password>"] — omit to read from docs/DEPLOY.md (min 8 chars)');
  process.exit(1);
}

const content = readFileSync(new URL('./content/content.json', import.meta.url), 'utf8');
JSON.parse(content); // fail fast on invalid JSON
const template = readFileSync(new URL('./src/template.html', import.meta.url), 'utf8');
if (!template.includes('"__PAYLOAD__"')) {
  console.error('Template is missing the "__PAYLOAD__" placeholder.');
  process.exit(1);
}

const b64 = (buf) => Buffer.from(buf).toString('base64');

async function deriveKey(pw, saltBytes) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: ITER, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
}

// Reuse the previous salt when the password is unchanged, so cached keys on
// Joseph's devices survive content rebuilds. The IV is always fresh (GCM nonce
// must never repeat under the same key); a stable public salt costs nothing.
let salt = crypto.getRandomValues(new Uint8Array(16));
try {
  const prev = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const m0 = prev.match(/const PAYLOAD = "([^"]+)"/);
  if (m0) {
    const p0 = JSON.parse(Buffer.from(m0[1], 'base64').toString('utf8'));
    const oldKey = await deriveKey(password, Buffer.from(p0.salt, 'base64'));
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(p0.iv, 'base64') }, oldKey, Buffer.from(p0.ct, 'base64'));
    salt = Buffer.from(p0.salt, 'base64'); // password unchanged -> keep salt
    console.log('salt reused — existing device unlocks stay valid');
  }
} catch { /* no previous build or password changed -> fresh salt */ }
const iv = crypto.getRandomValues(new Uint8Array(12));

const key = await deriveKey(password, salt);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(content));
const payload = Buffer.from(JSON.stringify({ v: 1, iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) })).toString('base64');

let out = template.replace('"__PAYLOAD__"', JSON.stringify(payload));

// CSP: hash the (single) inline script so the meta CSP pins exactly this code —
// inline event handlers and any injected <script> would be blocked by the browser.
const scriptSrc = out.match(/<script>([\s\S]*)<\/script>/);
if (!scriptSrc) { console.error('BUILD FAIL: inline script not found for CSP hash'); process.exit(1); }
const { createHash } = await import('node:crypto');
const cspHash = 'sha256-' + createHash('sha256').update(scriptSrc[1], 'utf8').digest('base64');
out = out.replace("'__CSPHASH__'", `'${cspHash}'`);
if (out.includes('__CSPHASH__')) { console.error('BUILD FAIL: CSP hash placeholder not replaced'); process.exit(1); }
writeFileSync(new URL('./index.html', import.meta.url), out);

// ── self-test: re-extract the payload from the written file, decrypt, compare ──
const written = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const m = written.match(/const PAYLOAD = "([^"]+)"/);
if (!m) { console.error('SELF-TEST FAIL: payload not found in index.html'); process.exit(1); }
const p = JSON.parse(Buffer.from(m[1], 'base64').toString('utf8'));
const key2 = await deriveKey(password, Buffer.from(p.salt, 'base64'));
const plain = new TextDecoder().decode(
  await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(p.iv, 'base64') }, key2, Buffer.from(p.ct, 'base64')),
);
if (plain !== content) { console.error('SELF-TEST FAIL: round-trip mismatch'); process.exit(1); }

// wrong-password must fail
let wrongOk = false;
try {
  const bad = await deriveKey(password + 'x', Buffer.from(p.salt, 'base64'));
  await crypto.subtle.decrypt({ name: 'AES-GCM', iv: Buffer.from(p.iv, 'base64') }, bad, Buffer.from(p.ct, 'base64'));
  wrongOk = true;
} catch { /* expected */ }
if (wrongOk) { console.error('SELF-TEST FAIL: wrong password decrypted successfully'); process.exit(1); }

console.log(`self-test OK — index.html ${(written.length / 1024).toFixed(0)} KB (content ${(content.length / 1024).toFixed(0)} KB, ${ITER.toLocaleString()} PBKDF2 iterations)`);
