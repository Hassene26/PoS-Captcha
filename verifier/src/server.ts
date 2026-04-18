import express from 'express';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import { challengeRouter } from './routes/challenge';
import { commitmentRouter } from './routes/commitment';
import { verifyRouter } from './routes/verify';
import { sessionRouter } from './routes/session';
import { sessionStore } from './session';
import { verifierPublicKeyPem } from './keys';
import path from 'path';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: true, // Allow all origins in dev; restrict in production
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));

// Serve the static test.html page and proxy script to bypass Brave 'file://' CORS blocks
app.use(express.static(path.join(__dirname, '../../')));

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', sessions: sessionStore.size() });
});

// Public key distribution for whitelisted websites to validate JWTs locally.
app.get('/.well-known/pos-captcha.pub', (_req, res) => {
  res.type('application/x-pem-file').send(verifierPublicKeyPem);
});

// Routes
app.use('/api/session', sessionRouter);
app.use('/api/commitment', commitmentRouter);
app.use('/api/challenge', challengeRouter);
app.use('/api/verify', verifyRouter);

app.listen(PORT, () => {
  console.log(`[Verifier] PoS-CAPTCHA Verifier running on http://localhost:${PORT}`);
  console.log(`[Verifier] Endpoints:`);
  console.log(`  POST /api/session/start         — Start a site-bound PoS session (signed intent)`);
  console.log(`  POST /api/commitment/register  — Register client commitment`);
  console.log(`  POST /api/challenge/issue       — Issue a new challenge`);
  console.log(`  POST /api/challenge/submit      — Submit proof response`);
  console.log(`  POST /api/verify/inclusion      — Submit inclusion proofs`);
  console.log(`  GET  /.well-known/pos-captcha.pub — Verifier Ed25519 public key (PEM)`);
});
