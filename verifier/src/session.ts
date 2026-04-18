import jwt from 'jsonwebtoken';
import { verifierPrivateKey, verifierPublicKey } from './keys';

const TOKEN_TTL = '5m'; // 5 minutes
const JWT_ISSUER = 'pos-captcha-verifier';

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

  return jwt.sign(
    {
      jti: tokenId,
      sessionId,
      sub: clientId,
      verified: true,
      iat: Math.floor(Date.now() / 1000),
    },
    verifierPrivateKey,
    {
      expiresIn: TOKEN_TTL,
      issuer: JWT_ISSUER,
      audience: siteId,
      algorithm: 'EdDSA',
    }
  );
}

/**
 * Verify a TTL token AND enforce the stateful NB_MAX usage limit.
 * `expectedAudience` should be the siteId the caller expects (typically
 * the website validating its own tokens). Omit only for internal diagnostics.
 */
export function verifyToken(token: string, expectedAudience?: string): any {
  try {
    const decoded = jwt.verify(token, verifierPublicKey, {
      algorithms: ['EdDSA'],
      issuer: JWT_ISSUER,
      audience: expectedAudience,
    }) as any;
    
    // Check stateful usage limit
    if (decoded && decoded.jti) {
      const isValidUsage = sessionStore.incrementTokenUsage(decoded.jti);
      if (!isValidUsage) {
        console.warn(`[TokenTracker] Token ${decoded.jti} rejected (Usage limit exceeded or unknown).`);
        return null;
      }
    }

    return decoded;
  } catch {
    return null;
  }
}
