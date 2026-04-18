import { Router, Request, Response } from 'express';
import { sessionStore } from '../session';
import { verifySignedIntent, SignedIntent } from '../websites';

export const sessionRouter = Router();

/**
 * POST /api/session/start
 *
 * A whitelisted website's backend creates a signedIntent and hands it to the
 * user's browser. The browser forwards it here to open a PoS session bound
 * to the website. On success, the caller proceeds with the normal commitment/
 * challenge/verify flow; a passing verification mints a JWT scoped to siteId.
 *
 * Body: {
 *   siteId: string,
 *   signedIntent: { payload: { siteId, nonce, ts }, signature: base64 }
 * }
 */
sessionRouter.post('/start', (req: Request, res: Response) => {
  const { siteId, signedIntent } = req.body as {
    siteId: string;
    signedIntent: SignedIntent;
  };

  if (!siteId || !signedIntent) {
    return res.status(400).json({ error: 'Missing siteId or signedIntent' });
  }
  if (signedIntent.payload?.siteId !== siteId) {
    return res.status(400).json({ error: 'siteId mismatch between body and intent' });
  }

  const check = verifySignedIntent(signedIntent);
  if (!check.ok) {
    return res.status(403).json({ error: check.reason });
  }

  // Create a fresh session pre-bound to this site. The seed will be set when
  // the challenge is issued.
  const session = sessionStore.create(0);
  session.siteId = siteId;
  sessionStore.update(session.sessionId, session);

  console.log(`[Session] Started for siteId=${siteId}, sessionId=${session.sessionId}`);

  res.json({
    sessionId: session.sessionId,
    siteId,
  });
});
