# PoS-CAPTCHA: Proof of Space Authentication System

> A novel approach to bot-prevention that uses cryptographic proof of allocated disk space (Proof of Space) instead of traditional image-based CAPTCHA puzzles to verify human authenticity.

## 📖 What I Did

I took the core cryptographic concepts from a master's thesis on "Proof of Space" (PoS) and transformed them into a fully functional, end-to-end CAPTCHA system.

Instead of asking users to "click all traffic lights", this system asks the user's computer to quickly read specific bytes scattered randomly across a dedicated 64MB file on their hard drive. Because of seek-time constraints across a physical disk, the response time proves that the user genuinely has that file stored and isn't generating the data mathematically on-the-fly.

### The System Architecture

The system is built across 5 distinct components:

1. **The Prover (Rust Daemon):**
   A lightweight local background service running on the user's machine (`localhost:7331`). It securely allocates 64MB of deterministic random data (the "Plot") derived from a seed. It serves an HTTP API (`actix-web`) that accepts challenges from the browser and reads bytes / Merkle proofs directly from the disk plot.

2. **The Verifier Native Bindings (Rust → NAPI-RS):**
   The core cryptographic verification math (Merkle root reconstruction, path chain derivation, inclusion proof checks) is compiled as a native `.node` binary via NAPI-RS and loaded by the Verifier server. This guarantees bit-for-bit identical logic between the Prover and the backend Verifier.

3. **The Verifier Server (TypeScript/Node.js):**
   The remote backend API (`localhost:3000`). It registers commitments, issues challenges, verifies the submitted proofs through the native bindings, signs per-site JWTs with EdDSA, and exposes its public key at `/.well-known/pos-captcha.pub` so whitelisted websites can validate tokens offline.

4. **The Proxy Widget (Vanilla JS/TS):**
   An embeddable frontend widget (`captcha-widget.js`) that acts as the orchestrator. It bridges the remote Verifier server and the local Prover daemon, handling the full encrypted handshake transparently.

5. **The Browser Extension (Manifest V3):**
   A Chrome/Brave extension providing visual feedback on the local Prover's status (Offline / Plotting / Ready / Proving) by polling the daemon's `/status` endpoint.

---

## ⚙️ Notable Implementation Details

- **End-to-end AES-256-GCM encryption.** Challenges, proof bytes, sampled targets, and inclusion proofs are encrypted between Verifier and Prover. The browser widget is a blind relay.
- **Byte-chained path generator.** Target *i+1* depends on the plot byte actually read at target *i*, so an attacker without the local plot cannot pre-compute the path from the seed alone. See [prover/src/communication/path_generator.rs](prover/src/communication/path_generator.rs) and [verifier/native/src/lib.rs](verifier/native/src/lib.rs).
- **Multi-tenant websites.** Websites are whitelisted by Ed25519 public key in `verifier/config/websites.json`. A login request requires a signed intent `{siteId, nonce, ts}` from the website's backend (±60 s freshness, nonce dedup). Issued JWTs are scoped to `aud = siteId` and signed with EdDSA; websites validate offline using the verifier's public key.
- **Token lifecycle.** JWTs die on whichever hits first: 5-minute TTL (stateless `exp`) or 5 successful uses (stateful `tokenUses[jti]` counter on the verifier).
- **Determinism without external files.** Plots are generated via a cryptographic CSPRNG (`rand_chacha`) — no `input.mp4` required.
- **Windows toolchain.** Cargo and NAPI both need `link.exe` (MSVC); run the build commands from an **x64 Native Tools Command Prompt for VS 2022** so `link.exe` is on PATH.

---

## 🚀 Running the Project

Three things must run simultaneously: the **Prover**, the **Verifier**, and the **browser** (with the optional status extension).

### Prerequisites

- Windows with **Visual Studio Build Tools 2022** (for MSVC linker).
- **Rust** (stable toolchain, `rustup`).
- **Node.js ≥ 18** and `npm`.
- `@napi-rs/cli` globally: `npm i -g @napi-rs/cli`.

### Step 0: Build the verifier's native bindings (first time only)

Open the **x64 Native Tools Command Prompt for VS 2022** (Start menu):

```cmd
cd verifier\native
napi build --release
```

This produces `verifier/native/pos-native.<platform>.node`, which the Verifier server loads at runtime.

### Step 1: Configure environment

The Prover needs an AES key shared with the Verifier:

```cmd
set AES_SECRET_KEY=<64-hex-char string>
```

Generate one with e.g. `openssl rand -hex 32`. **Both** the Prover and the Verifier must see the same value. (There's a TODO in the roadmap to replace this with a Diffie-Hellman exchange.)

`JWT_SECRET` is no longer needed — the verifier now signs JWTs with its Ed25519 private key, auto-generated on first run at `verifier/config/verifier-keys/`.

### Step 2: Whitelist at least one website

Edit `verifier/config/websites.json`:

```json
{
  "websites": [
    {
      "id": "localhost-test",
      "publicKey": "<base64 Ed25519 SPKI DER or PEM>",
      "registeredAt": "2026-04-18"
    }
  ]
}
```

To generate a keypair for testing:

```bash
node -e "const c=require('crypto');const {publicKey,privateKey}=c.generateKeyPairSync('ed25519');console.log('PUB:',publicKey.export({format:'der',type:'spki'}).toString('base64'));console.log('PRIV:',privateKey.export({format:'pem',type:'pkcs8'}));"
```

Paste the `PUB:` string into `publicKey` and keep the private key for the website backend that issues signed intents.

### Step 3: Start the Prover

In a terminal in the project root:

```cmd
run_prover.bat
```

The Rust service binds `127.0.0.1:7331`. First launch takes ~10 s to generate the 64MB plot. Leave the window open.

### Step 4: Start the Verifier

In a **new** terminal:

```cmd
cd verifier
npm install        (first time only)
npm run dev
```

This starts the backend at `http://localhost:3000`. On first run the verifier creates its Ed25519 keypair under `verifier/config/verifier-keys/` (gitignored). Its public key is served at `GET /.well-known/pos-captcha.pub`.

### Step 5: Load the Browser Extension (optional but useful)

1. Chrome/Brave → `chrome://extensions/`.
2. Toggle **Developer mode** ON.
3. **Load unpacked** → select the `extension/` folder.
4. Pin **PoS-CAPTCHA Status** to the toolbar — it should show 🟢 Ready.

### Step 6: Try the flow

Open [http://localhost:3000/test.html](http://localhost:3000/test.html). Click the PoS-CAPTCHA widget and watch the sequence:

```
Checking local service  →  Verifying storage proof  →  Verified ✅
```

On success the widget displays the JWT. The same token can be validated by any whitelisted website backend using the verifier's public key — no callback to the verifier needed.

---

## 🔁 Everyday Testing Cheat Sheet

Once the one-time setup (Steps 0 and 2 above) is done, a full test run is just **two terminals + a browser tab**. The AES key, the verifier keypair, and the website whitelist all persist on disk between runs.

### Terminal A — Prover

```cmd
set AES_SECRET_KEY=<same 64-hex value you picked during setup>
run_prover.bat
```

Wait for `Prover ready on 127.0.0.1:7331`.

### Terminal B — Verifier

```cmd
cd verifier
set AES_SECRET_KEY=<same value as Terminal A>
npm run dev
```

Wait for `Verifier listening on http://localhost:3000`.

### Browser

Open [http://localhost:3000/test.html](http://localhost:3000/test.html) and click the widget.

> 💡 Tip: put both `set AES_SECRET_KEY=...` + start command into a tiny `.bat` per terminal so each run is one double-click.

### When to redo more than that

| You changed…                                  | Extra step                                  |
| --------------------------------------------- | ------------------------------------------- |
| Rust code in `verifier/native/`               | `cd verifier\native && napi build --release` (x64 Native Tools prompt) |
| Rust code in `prover/`                        | Rebuild happens automatically via `run_prover.bat` |
| `verifier/config/websites.json`               | Restart Terminal B                          |
| TypeScript in `verifier/src/`                 | `ts-node-dev` auto-reloads — nothing to do  |
| TypeScript in `proxy/src/`                    | `cd proxy && npm run build`                 |
| Want a fresh Site X keypair                   | Clear localStorage for `test.html`, refresh, paste the new snippet into `websites.json`, restart Terminal B |

---

## 🔧 Protocol Flow (one login)

1. **Session start.** Site X's backend signs `{siteId, nonce, ts}` with its Ed25519 private key and hands the blob to the user's browser. The widget posts it to `POST /api/session/start`; the verifier checks signature, freshness, and nonce-replay, then opens a session bound to `siteId`.
2. **Commitment.** Widget asks the local Prover for its 64MB plot's Merkle root hashes and sends them to `POST /api/commitment/register`.
3. **Challenge.** Verifier picks a random seed, encrypts `{seed, sessionId}` with AES-GCM, and returns it (`POST /api/challenge/issue`).
4. **Proving.** Widget forwards the encrypted blob to the Prover. The Prover runs the byte-chained path generator for 70 iterations: each target depends on the plot byte read at the previous target. Returns 70 bytes (AES-encrypted).
5. **Path reconstruction + sampling.** Verifier calls `derivePathChain(seed, numBlockGroups, proofBytes)` in native Rust to rebuild the target chain, samples 1%, and asks the Prover for Merkle inclusion proofs on those targets.
6. **Verification.** Verifier checks the 2-second time bound and Merkle inclusion against the committed root hashes. On success, it signs an EdDSA JWT with `aud = siteId`, `exp = +5 min`, `jti = uuid`, and returns it.
7. **Site-side login.** User presents the JWT to site X. Site X validates it offline (`alg = EdDSA`, `aud == siteId`, `exp`) using the cached verifier public key. No callback required.
