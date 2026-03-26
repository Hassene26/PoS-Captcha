import { Router, Request, Response } from 'express';
import { sessionStore, CommitmentData } from '../session';

export const commitmentRouter = Router();

/**
 * POST /api/commitment/register
 * 
 * Phase 1: The client (Prover) registers its commitment (Merkle root hashes)
 * with the Verifier.
 * 
 * Body: {
 *   clientId: string,           // Unique identifier for this client
 *   rootHashes: string[],       // Hex-encoded root hashes for each block group
 *   numBlockGroups: number
 * }
 */
commitmentRouter.post('/register', (req: Request, res: Response) => {
  const { clientId, rootHashes, numBlockGroups } = req.body;

  if (!clientId || !rootHashes || !numBlockGroups) {
    return res.status(400).json({
      error: 'Missing required fields: clientId, rootHashes, numBlockGroups',
    });
  }

  if (!Array.isArray(rootHashes) || rootHashes.length === 0) {
    return res.status(400).json({
      error: 'rootHashes must be a non-empty array of hex strings',
    });
  }

  const commitment: CommitmentData = {
    rootHashes,
    numBlockGroups,
    registeredAt: Date.now(),
    clientId,
  };

  sessionStore.registerCommitment(clientId, commitment);

  console.log(`[Commitment] Registered commitment for client ${clientId}: ${numBlockGroups} block groups`);

  res.json({
    success: true,
    clientId,
    numBlockGroups,
    registeredAt: commitment.registeredAt,
  });
});

/**
 * GET /api/commitment/:clientId
 * 
 * Check if a client has a registered commitment.
 */
commitmentRouter.get('/:clientId', (req: Request, res: Response) => {
  const { clientId } = req.params;
  const commitment = sessionStore.getCommitment(clientId);

  if (!commitment) {
    return res.status(404).json({ error: 'No commitment found for this client' });
  }

  res.json({
    clientId: commitment.clientId,
    numBlockGroups: commitment.numBlockGroups,
    registeredAt: commitment.registeredAt,
    numHashes: commitment.rootHashes.length,
  });
});
