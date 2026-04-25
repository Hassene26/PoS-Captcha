import { Router, Request, Response } from 'express';
import { sessionStore, issueToken, verifyToken } from '../session';
import { verifyInclusionProof, verifyTimeBound } from '../../native';
import { decryptAES } from '../crypto';
import { Buffer } from 'buffer';

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
  const { sessionId, encryptedInclusionBlob } = req.body;

  if (!sessionId || !encryptedInclusionBlob) {
    return res.status(400).json({ error: 'Missing sessionId or encryptedInclusionBlob' });
  }

  let inclusionData;
  try {
    inclusionData = decryptAES(encryptedInclusionBlob);
  } catch (err) {
    return res.status(400).json({ error: 'Failed to decrypt inclusion blob' });
  }
  
  const inclusionProofs = inclusionData.proofs;

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
  const wallMs = (session.proofReceivedAt || Date.now()) - (session.challengeIssuedAt || 0);
  // Subtract human reaction time spent in the consent popup — the 2 s bound
  // applies to disk reads, not to how fast the user clicks "Allow".
  const elapsedMs = Math.max(0, wallMs - (session.consentWaitMs || 0));

  // Call the native Rust verification for the 2000ms bound
  const timeCheckPassed = verifyTimeBound(elapsedMs);

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
      try {
        const rootHashBuf = Buffer.from(root_hash);
        const formattedSiblings = merkleProof.siblings.map((sib: any) => ({
          hash: Buffer.from(sib.hash),
          direction: sib.direction
        }));
        
        const selfFragmentBuf = Buffer.from(self_fragment || []);
        
        valid = verifyInclusionProof(selfFragmentBuf, formattedSiblings, rootHashBuf);
        reason = valid ? 'Verified securely via Native Rust binding' : 'Inclusion proof mathematically invalid';
      } catch (err) {
        reason = `Native binding err: ${err}`;
      }
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

  // Issue TTL token if passed. Requires the session to be bound to a whitelisted site.
  let token: string | null = null;
  if (passed && commitment.clientId && session.siteId) {
    token = issueToken(sessionId, commitment.clientId, session.siteId);
  } else if (passed && !session.siteId) {
    console.warn(`[Verify] Session ${sessionId} passed but has no siteId — no token issued.`);
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

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(401).json({ valid: false, error: 'Invalid token, expired, or maximum usage limit reached.' });
  }

  res.json({ valid: true, decoded });
});
