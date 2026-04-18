import fs from 'fs';
import path from 'path';
import crypto, { KeyObject } from 'crypto';

/**
 * Loads (or generates on first run) the verifier's Ed25519 keypair.
 * The private key signs JWTs (EdDSA). The public key is served at
 * GET /.well-known/pos-captcha.pub so whitelisted websites can
 * validate tokens locally without calling back to the verifier.
 *
 * Storage: PEM files under VERIFIER_KEY_PATH (default
 * `verifier/config/verifier-keys/`). Both files are gitignored.
 */

const KEY_DIR =
  process.env.VERIFIER_KEY_PATH ||
  path.join(__dirname, '..', 'config', 'verifier-keys');
const PRIV_PATH = path.join(KEY_DIR, 'ed25519.pem');
const PUB_PATH = path.join(KEY_DIR, 'ed25519.pub');

function generateAndPersist(): { privateKey: KeyObject; publicKey: KeyObject } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');

  fs.mkdirSync(KEY_DIR, { recursive: true });
  fs.writeFileSync(
    PRIV_PATH,
    privateKey.export({ format: 'pem', type: 'pkcs8' }),
    { mode: 0o600 }
  );
  fs.writeFileSync(
    PUB_PATH,
    publicKey.export({ format: 'pem', type: 'spki' })
  );
  console.log(`[Keys] Generated new Ed25519 keypair at ${KEY_DIR}`);
  return { privateKey, publicKey };
}

function load(): { privateKey: KeyObject; publicKey: KeyObject } {
  if (!fs.existsSync(PRIV_PATH) || !fs.existsSync(PUB_PATH)) {
    return generateAndPersist();
  }
  const privateKey = crypto.createPrivateKey(fs.readFileSync(PRIV_PATH));
  const publicKey = crypto.createPublicKey(fs.readFileSync(PUB_PATH));
  console.log(`[Keys] Loaded Ed25519 keypair from ${KEY_DIR}`);
  return { privateKey, publicKey };
}

const { privateKey, publicKey } = load();

export const verifierPrivateKey: KeyObject = privateKey;
export const verifierPublicKey: KeyObject = publicKey;

/** SPKI PEM of the verifier's public key — served at /.well-known. */
export const verifierPublicKeyPem: string = publicKey
  .export({ format: 'pem', type: 'spki' })
  .toString();
