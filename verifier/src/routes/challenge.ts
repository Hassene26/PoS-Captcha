import { Router, Request, Response } from 'express';
import { sessionStore } from '../session';
import { encryptAES, decryptAES } from '../crypto';
import { derivePathChain } from '../../native';

export const challengeRouter = Router();

/**
 * POST /api/challenge/issue
 * 
 * Phase 2, Step 1: Issue a new challenge to the browser proxy.
 * The Verifier generates a random seed and session ID.
 * 
 * Body: {
 *   clientId: string   // Must have a registered commitment
 * }
 * 
 * Response: {
 *   sessionId: string,
 *   seed: number,       // Random seed for the challenge
 * }
 */
challengeRouter.post('/issue', (req: Request, res: Response) => {
  const { clientId } = req.body;

  if (!clientId) {
    return res.status(400).json({ error: 'Missing clientId' });
  }

  // Check that the client has a registered commitment
  const commitment = sessionStore.getCommitment(clientId);
  if (!commitment) {
    return res.status(404).json({
      error: 'No commitment found. Client must register first via POST /api/commitment/register',
    });
  }

  // Generate random seed (0-254)
  const seed = Math.floor(Math.random() * 255);

  // Create session
  const session = sessionStore.create(seed);
  session.status = 'challenged';
  session.challengeIssuedAt = Date.now();
  session.commitment = commitment;

  sessionStore.update(session.sessionId, session);

  console.log(`[Challenge] Issued challenge: session=${session.sessionId}, client=${clientId}`);

  const payloadToEncrypt = { seed, session_id: session.sessionId };
  const encryptedChallengeBlob = encryptAES(payloadToEncrypt);

  res.json({
    sessionId: session.sessionId,
    encryptedChallengeBlob,
  });
});

/**
 * POST /api/challenge/submit
 * 
 * Phase 2, Step 5: The browser proxy submits the proof bytes
 * received from the local Prover.
 * 
 * Body: {
 *   sessionId: string,
 *   proofBytes: number[],    // Byte values read from the Prover's disk
 *   seed: number,            // Returned seed from the Prover
 *   iteration: number,       // Returned iteration count
 * }
 */
challengeRouter.post('/submit', (req: Request, res: Response) => {
  const { sessionId, encryptedProofBlob } = req.body;

  if (!sessionId || !encryptedProofBlob) {
    return res.status(400).json({ error: 'Missing sessionId or encryptedProofBlob' });
  }

  const session = sessionStore.get(sessionId);
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }

  if (session.status !== 'challenged') {
    return res.status(400).json({ error: `Invalid session status: ${session.status}` });
  }

  let proofData;
  try {
    proofData = decryptAES(encryptedProofBlob);
  } catch (err) {
    return res.status(400).json({ error: 'Failed to decrypt proof blob' });
  }

  const { proof_bytes, seed, iteration } = proofData;

  // Record the proof and timing
  session.proofReceivedAt = Date.now();
  session.proofBytes = proof_bytes;
  session.expectedSeed = seed;
  session.expectedIteration = iteration;
  session.status = 'verifying';
  sessionStore.update(sessionId, session);

  const elapsedMs = session.proofReceivedAt - (session.challengeIssuedAt || session.proofReceivedAt);

  console.log(`[Challenge] Proof received: session=${sessionId}, ${proof_bytes.length} bytes, elapsed=${elapsedMs}ms`);

  // Re-derive the target chain from the original seed AND the bytes the Prover returned.
  // Because target i+1 depends on byte i (rolled into the seed), the verifier can only
  // reconstruct the path by walking the returned bytes — which is exactly what binds the
  // Prover to having done real sequential disk reads.
  const numBlockGroups = session.commitment!.numBlockGroups;
  const originalSeed = session.seed;
  const BATCH_SIZE = 70; // Must match Prover

  const proofBytesBuf = Buffer.from(proof_bytes);
  const allPaths = derivePathChain(originalSeed, numBlockGroups, proofBytesBuf);
  
  // Sample 1% of the queried bytes (minimum 1 target) to verify their Merkle Inclusion
  const VERIFIABLE_RATIO = 0.01;
  const sampleSize = Math.max(1, Math.floor(BATCH_SIZE * VERIFIABLE_RATIO));
  const selectedTargets = [];

  for (let i = 0; i < sampleSize; i++) {
    const randomIdx = Math.floor(Math.random() * allPaths.length);
    const target = allPaths[randomIdx];
    selectedTargets.push([target.blockId, target.index]);
    allPaths.splice(randomIdx, 1); // remove to prevent duplicates
  }

  const targetsPayload = { targets: selectedTargets };
  const encryptedTargetsBlob = encryptAES(targetsPayload);

  res.json({
    sessionId,
    status: 'verifying',
    elapsedMs,
    proofCount: proof_bytes.length,
    encryptedTargetsBlob,
    message: 'Proof received. Proceed to POST /api/verify/inclusion.',
  });
});
