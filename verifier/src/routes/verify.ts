import { Router, Request, Response } from 'express';
import { sessionStore, issueToken } from '../session';

export const verifyRouter = Router();

/**
 * POST /api/verify/inclusion
 * 
 * Phase 2, Step 6: The browser proxy submits inclusion proofs
 * from the Prover. The Verifier checks:
 *   1. Temporal Integrity — response time is consistent with disk reads
 *   2. Cryptographic Correctness — inclusion proofs match the commitment
 * 
 * Body: {
 *   sessionId: string,
 *   inclusionProofs: Array<{
 *     block_id: number,
 *     position: number,
 *     root_hash: number[],       // 32 bytes
 *     self_fragment: number[],   // 32 bytes
 *     proof: { siblings: Array<{ hash: number[], direction: "Left"|"Right" }> }
 *   }>
 * }
 * 
 * NOTE: In production, these will be verified using the Wasm module.
 * For now, we perform a simplified check and demonstrate the flow.
 */
verifyRouter.post('/inclusion', (req: Request, res: Response) => {
  const { sessionId, inclusionProofs } = req.body;

  if (!sessionId || !inclusionProofs) {
    return res.status(400).json({ error: 'Missing sessionId or inclusionProofs' });
  }

  const session = sessionStore.get(sessionId);
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }

  if (session.status !== 'verifying') {
    return res.status(400).json({ error: `Invalid session status: ${session.status}` });
  }

  const commitment = session.commitment;
  if (!commitment) {
    return res.status(400).json({ error: 'No commitment linked to this session' });
  }

  // ========== Temporal Integrity Check ==========
  const elapsedMs = (session.proofReceivedAt || Date.now()) - (session.challengeIssuedAt || 0);
  const elapsedMicros = elapsedMs * 1000;
  const numProofs = session.proofBytes?.length || 0;

  // Simplified time check: ensure response came within 2 seconds
  // In production, use the Wasm verify_time_bound() function
  const timeCheckPassed = elapsedMs < 2000;

  // ========== Cryptographic Correctness Check ==========
  // Verify each inclusion proof against the committed root hashes.
  // In production, call the Wasm verify_inclusion_proof() for each.
  const results: Array<{ block_id: number; position: number; valid: boolean; reason: string }> = [];
  let allValid = true;

  for (const proof of inclusionProofs) {
    const { block_id, position, root_hash, self_fragment, proof: merkleProof } = proof;

    // Check that the root_hash in the proof matches the committed root hash for this block
    const committedHash = commitment.rootHashes[block_id];
    const proofRootHex = Array.isArray(root_hash)
      ? root_hash.map((b: number) => b.toString(16).padStart(2, '0')).join('')
      : '';

    let valid = false;
    let reason = '';

    if (!committedHash) {
      reason = `No committed hash for block_id ${block_id}`;
    } else if (committedHash !== proofRootHex) {
      reason = `Root hash mismatch: committed=${committedHash}, proof=${proofRootHex}`;
    } else if (!merkleProof || !merkleProof.siblings || merkleProof.siblings.length === 0) {
      reason = 'Empty Merkle proof';
    } else {
      // TODO: In production, call Wasm verify_inclusion_proof() here
      // For now, mark as valid if root hash matches commitment
      valid = true;
      reason = 'Root hash matches commitment (full Merkle verification pending Wasm integration)';
    }

    if (!valid) {
      allValid = false;
    }

    results.push({ block_id, position, valid, reason });
  }

  // ========== Final Verdict ==========
  const passed = timeCheckPassed && allValid;
  session.status = passed ? 'passed' : 'failed';
  sessionStore.update(sessionId, session);

  // Issue TTL token if passed
  let token: string | null = null;
  if (passed && commitment.clientId) {
    token = issueToken(sessionId, commitment.clientId);
  }

  const response: any = {
    sessionId,
    status: session.status,
    timeCheck: {
      passed: timeCheckPassed,
      elapsedMs,
    },
    correctnessCheck: {
      passed: allValid,
      totalProofs: inclusionProofs.length,
      results,
    },
  };

  if (token) {
    response.token = token;
    response.message = 'Verification passed! Use the token to access protected resources.';
  } else {
    response.message = 'Verification failed.';
  }

  console.log(`[Verify] Session ${sessionId}: ${session.status} (time=${elapsedMs}ms, proofs=${inclusionProofs.length})`);

  res.json(response);
});

/**
 * POST /api/verify/token
 * 
 * Validate a previously issued TTL token.
 * 
 * Body: { token: string }
 */
verifyRouter.post('/token', (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Missing token' });
  }

  const decoded = require('jsonwebtoken').verify(token, process.env.JWT_SECRET || 'pos-captcha-secret-change-in-production');
  if (!decoded) {
    return res.status(401).json({ valid: false, error: 'Invalid or expired token' });
  }

  res.json({ valid: true, decoded });
});
