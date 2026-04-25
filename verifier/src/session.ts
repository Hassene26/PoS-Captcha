import crypto from 'crypto';
import { verifierPrivateKey, verifierPublicKey } from './keys';

const TOKEN_TTL_SECONDS = 5 * 60; // 5 minutes
const JWT_ISSUER = 'pos-captcha-verifier';

// We sign JWTs with EdDSA directly via Node's crypto, because jsonwebtoken@9.0.3
// hard-codes its algorithm allowlist and does not include 'EdDSA'.
function b64url(buf: Buffer | string): string {
  const b = typeof buf === 'string' ? Buffer.from(buf) : buf;
  return b.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64urlDecode(s: string): Buffer {
  const pad = (4 - (s.length % 4)) % 4;
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad), 'base64');
}

function signJwtEdDSA(payload: object, privateKey: crypto.KeyObject): string {
  const header = { alg: 'EdDSA', typ: 'JWT' };
  const head = b64url(JSON.stringify(header));
  const body = b64url(JSON.stringify(payload));
  const signingInput = `${head}.${body}`;
  const sig = crypto.sign(null, Buffer.from(signingInput), privateKey);
  return `${signingInput}.${b64url(sig)}`;
}

function verifyJwtEdDSA(
  token: string,
  publicKey: crypto.KeyObject
): { header: any; payload: any } | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [head, body, sig] = parts;
  const signingInput = `${head}.${body}`;
  const sigBuf = b64urlDecode(sig);
  const ok = crypto.verify(null, Buffer.from(signingInput), publicKey, sigBuf);
  if (!ok) return null;
  try {
    const header = JSON.parse(b64urlDecode(head).toString('utf8'));
    const payload = JSON.parse(b64urlDecode(body).toString('utf8'));
    if (header.alg !== 'EdDSA') return null;
    return { header, payload };
  } catch {
    return null;
  }
}

export interface SessionData {
  sessionId: string;
  seed: number;               // Random seed for the challenge
  createdAt: number;          // Timestamp ms
  challengeIssuedAt?: number; // When the challenge was sent
  proofReceivedAt?: number;   // When the proof was received
  status: 'pending_commitment' | 'committed' | 'challenged' | 'verifying' | 'passed' | 'failed';
  siteId?: string;            // Whitelisted website this session is bound to
  commitment?: CommitmentData;
  proofBytes?: number[];
  expectedSeed?: number;      // Seed after proof batch
  expectedIteration?: number;
  consentWaitMs?: number;     // Time the prover spent waiting for user consent
}

export interface CommitmentData {
  rootHashes: string[];   // Hex-encoded root hashes
  numBlockGroups: number;
  registeredAt: number;
  clientId: string;
}

/**
 * Simple in-memory session store.
 * In production, replace with Redis or a DB.
 */
class SessionStore {
  private sessions: Map<string, SessionData> = new Map();
  private commitments: Map<string, CommitmentData> = new Map(); // clientId -> commitment
  private tokenUses: Map<string, number> = new Map();
  private readonly NB_MAX = 5; // Max allowed uses for a single token

  create(seed: number): SessionData {
    const sessionId = require('uuid').v4();
    const session: SessionData = {
      sessionId,
      seed,
      createdAt: Date.now(),
      status: 'pending_commitment',
    };
    this.sessions.set(sessionId, session);
    return session;
  }

  get(sessionId: string): SessionData | undefined {
    return this.sessions.get(sessionId);
  }

  update(sessionId: string, data: Partial<SessionData>): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      Object.assign(session, data);
    }
  }

  delete(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  size(): number {
    return this.sessions.size;
  }

  // Commitment management
  registerCommitment(clientId: string, commitment: CommitmentData): void {
    this.commitments.set(clientId, commitment);
  }

  getCommitment(clientId: string): CommitmentData | undefined {
    return this.commitments.get(clientId);
  }

  // Stateful Token Management
  registerToken(tokenId: string): void {
    this.tokenUses.set(tokenId, 0);
  }

  incrementTokenUsage(tokenId: string): boolean {
    const uses = this.tokenUses.get(tokenId);
    if (uses === undefined) return false; // Token was never issued by this server
    if (uses >= this.NB_MAX) return false; // Exceeded NB_MAX limit
    
    this.tokenUses.set(tokenId, uses + 1);
    console.log(`[TokenTracker] Token ${tokenId} used ${uses + 1}/${this.NB_MAX} times.`);
    return true;
  }
}

export const sessionStore = new SessionStore();

/**
 * Issue a signed TTL token for a verified client, scoped to a specific website.
 * Signed with the verifier's Ed25519 private key (EdDSA). Websites validate
 * locally using the public key exposed at /.well-known/pos-captcha.pub.
 */
export function issueToken(sessionId: string, clientId: string, siteId: string): string {
  const tokenId = require('uuid').v4();
  sessionStore.registerToken(tokenId);

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    jti: tokenId,
    sessionId,
    sub: clientId,
    aud: siteId,
    iss: JWT_ISSUER,
    verified: true,
    iat: now,
    exp: now + TOKEN_TTL_SECONDS,
  };
  return signJwtEdDSA(payload, verifierPrivateKey);
}

/**
 * Verify a TTL token AND enforce the stateful NB_MAX usage limit.
 * `expectedAudience` should be the siteId the caller expects (typically
 * the website validating its own tokens). Omit only for internal diagnostics.
 */
export function verifyToken(token: string, expectedAudience?: string): any {
  const result = verifyJwtEdDSA(token, verifierPublicKey);
  if (!result) return null;
  const { payload } = result;

  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== JWT_ISSUER) return null;
  if (typeof payload.exp !== 'number' || payload.exp <= now) return null;
  if (expectedAudience !== undefined && payload.aud !== expectedAudience) return null;

  if (payload.jti) {
    const isValidUsage = sessionStore.incrementTokenUsage(payload.jti);
    if (!isValidUsage) {
      console.warn(`[TokenTracker] Token ${payload.jti} rejected (Usage limit exceeded or unknown).`);
      return null;
    }
  }

  return payload;
}
