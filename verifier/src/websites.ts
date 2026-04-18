import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/**
 * Whitelisted websites that are allowed to initiate PoS-Captcha sessions.
 * Registration is manual: edit verifier/config/websites.json.
 *
 * Each request a website makes to initiate a session must carry a
 * `signedIntent` — a JSON payload signed with the website's Ed25519
 * private key. The verifier checks the signature against the registered
 * public key, enforces a ±60 s freshness window on the timestamp, and
 * remembers the nonce for a short TTL to prevent replays.
 */

const CONFIG_PATH =
  process.env.WEBSITES_CONFIG_PATH ||
  path.join(__dirname, '..', 'config', 'websites.json');

export interface WebsiteRecord {
  id: string;
  publicKey: string; // base64-encoded raw Ed25519 SPKI DER or PEM
  registeredAt: string;
}

interface WebsitesConfig {
  websites: WebsiteRecord[];
}

function loadConfig(): Map<string, crypto.KeyObject> {
  const map = new Map<string, crypto.KeyObject>();
  if (!fs.existsSync(CONFIG_PATH)) {
    console.warn(`[Websites] No whitelist at ${CONFIG_PATH} — no sites authorized.`);
    return map;
  }
  const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
  const cfg: WebsitesConfig = JSON.parse(raw);
  for (const site of cfg.websites) {
    try {
      // Accept PEM or base64 DER
      const keyInput = site.publicKey.includes('BEGIN PUBLIC KEY')
        ? site.publicKey
        : Buffer.from(site.publicKey, 'base64');
      const keyObj = crypto.createPublicKey({
        key: keyInput as any,
        format: typeof keyInput === 'string' ? 'pem' : 'der',
        type: 'spki',
      });
      map.set(site.id, keyObj);
      console.log(`[Websites] Registered site: ${site.id}`);
    } catch (err) {
      console.error(`[Websites] Failed to load key for ${site.id}: ${err}`);
    }
  }
  return map;
}

const sites = loadConfig();

const INTENT_TTL_MS = 60_000; // ±60 s freshness window
const seenNonces = new Map<string, number>(); // nonce -> firstSeenMs

function sweepNonces(): void {
  const now = Date.now();
  for (const [nonce, ts] of seenNonces) {
    if (now - ts > INTENT_TTL_MS * 2) seenNonces.delete(nonce);
  }
}

export interface SignedIntent {
  payload: {
    siteId: string;
    nonce: string;
    ts: number; // ms since epoch
  };
  signature: string; // base64
}

export interface IntentCheckResult {
  ok: boolean;
  reason?: string;
}

/** Verify a signedIntent: siteId whitelisted, sig valid, ts fresh, nonce unused. */
export function verifySignedIntent(intent: SignedIntent): IntentCheckResult {
  const { payload, signature } = intent || ({} as SignedIntent);
  if (!payload || !signature) return { ok: false, reason: 'Malformed intent' };

  const { siteId, nonce, ts } = payload;
  if (!siteId || !nonce || typeof ts !== 'number') {
    return { ok: false, reason: 'Missing siteId/nonce/ts' };
  }

  const key = sites.get(siteId);
  if (!key) return { ok: false, reason: `Unknown siteId: ${siteId}` };

  const now = Date.now();
  if (Math.abs(now - ts) > INTENT_TTL_MS) {
    return { ok: false, reason: 'Intent timestamp outside freshness window' };
  }

  sweepNonces();
  if (seenNonces.has(nonce)) {
    return { ok: false, reason: 'Nonce replay detected' };
  }

  // Canonical JSON serialization (stable key order) for signature
  const canonical = JSON.stringify({ siteId, nonce, ts });
  const sigOk = crypto.verify(
    null, // Ed25519 ignores hash arg
    Buffer.from(canonical),
    key,
    Buffer.from(signature, 'base64')
  );
  if (!sigOk) return { ok: false, reason: 'Invalid signature' };

  seenNonces.set(nonce, now);
  return { ok: true };
}

export function isWhitelisted(siteId: string): boolean {
  return sites.has(siteId);
}
