import { Router, Request, Response } from 'express';
import { sessionStore } from '../session';

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

  console.log(`[Challenge] Issued challenge: session=${session.sessionId}, seed=${seed}, client=${clientId}`);

  res.json({
    sessionId: session.sessionId,
    seed,
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
  const { sessionId, proofBytes, seed, iteration } = req.body;

  if (!sessionId || !proofBytes) {
    return res.status(400).json({ error: 'Missing sessionId or proofBytes' });
  }

  const session = sessionStore.get(sessionId);
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }

  if (session.status !== 'challenged') {
    return res.status(400).json({ error: `Invalid session status: ${session.status}` });
  }

  // Record the proof and timing
  session.proofReceivedAt = Date.now();
  session.proofBytes = proofBytes;
  session.expectedSeed = seed;
  session.expectedIteration = iteration;
  session.status = 'verifying';
  sessionStore.update(sessionId, session);

  const elapsedMs = session.proofReceivedAt - (session.challengeIssuedAt || session.proofReceivedAt);

  console.log(`[Challenge] Proof received: session=${sessionId}, ${proofBytes.length} bytes, elapsed=${elapsedMs}ms`);

  res.json({
    sessionId,
    status: 'verifying',
    elapsedMs,
    proofCount: proofBytes.length,
    message: 'Proof received. Proceed to POST /api/verify/inclusion for correctness verification.',
  });
});
