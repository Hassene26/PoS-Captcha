# Changelog — Post cf76e66

All changes made to the PoS-Captcha project after commit `cf76e66`, organized by area.

---

## 1. Wasm Layer Removed (`0872a1b`)

The entire `verifier/wasm/` module was **deleted** — 294 lines of Rust + its `Cargo.toml`.

### What was removed

- **`verifier/wasm/src/lib.rs`** — Contained four `#[wasm_bindgen]` exported functions:
  - `generate_expected_path()` — Deterministic path generation using `DefaultHasher`
  - `verify_time_bound()` — Statistical confidence-interval analysis for timing (good vs bad proof ratios, mean/std-dev, 99% CI)
  - `verify_inclusion_proof()` — Full Merkle root recomputation from proof path + committed hash comparison
  - `select_verification_targets()` — Sampling logic to pick which proofs to verify
- **`verifier/wasm/Cargo.toml`** — Dependencies: `wasm-bindgen`, `serde`, `blake3`, `rand`, `getrandom` with `js` feature

### Why

The Wasm module required `wasm-pack` builds, browser-compatible `getrandom`, and a complex build pipeline. It was replaced by native NAPI Rust bindings that run server-side (see section 2).

---

## 2. Native Rust Bindings Added (`541d9b8`)

A new `verifier/native/` module was created — a NAPI-RS crate that compiles to a platform-specific `.node` binary, callable directly from TypeScript.

### What was added

- **`verifier/native/src/lib.rs`** (102 lines) — Three exported functions:

  - **`randomPathGenerator(seed, iterations, numBlockGroups)`**
    Deterministic path generation using a Linear Congruential Generator (LCG). Takes the challenge seed and reproduces the exact `(blockId, index)` pairs the Prover should have queried. Returns a `Vec<PositionTarget>`.

  - **`verifyInclusionProof(selfFragment, proofPath, expectedRootHash)`**
    Recomputes the Merkle root from a leaf fragment by hashing it with Blake3, then walking the sibling path (Left/Right concatenation). Returns `true` if the computed root matches the expected root hash.

  - **`verifyTimeBound(timestampDiffMs)`**
    Checks whether the proof response time is under 2000ms. This is a simplified version of the Wasm module's statistical analysis (which computed confidence intervals); the native version performs a straightforward threshold check.

- **`verifier/native/Cargo.toml`** — Dependencies: `napi`, `napi-derive`, `blake3`, `rand`
- **`verifier/native/build.rs`** — NAPI build script
- **`verifier/native/index.js`** — Platform detection loader (darwin/linux/windows, x64/arm64/ia32)
- **`verifier/native/index.d.ts`** — Auto-generated TypeScript type declarations
- **`verifier/native/package.json`** — NAPI package config with `@napi-rs/cli` dev dependency

### Key difference from Wasm

| Aspect | Old (Wasm) | New (Native) |
|--------|-----------|-------------|
| Path generator | `DefaultHasher` (Rust std) | LCG (`wrapping_mul` + `wrapping_add`) |
| Time verification | Statistical CI analysis | Simple `< 2000ms` threshold |
| Inclusion proofs | Full 3-step check (proof root, commitment root, both match) | 2-step check (leaf hash + path walk, compare to expected root) |
| Build | `wasm-pack` → `.wasm` blob | `cargo build` → `.node` binary |
| Runtime | Browser or Node via Wasm | Node.js only via NAPI |

---

## 3. End-to-End Encryption Added (`c23485c`, `541d9b8`, `6077184`)

All communication between the Prover and Verifier is now encrypted with **AES-256-GCM**. The browser widget acts as a blind relay — it passes encrypted blobs without being able to read them.

### Prover side

- **`prover/src/crypto.rs`** (new file, 47 lines)
  - `encrypt_aes(json_payload, hex_key)` — Encrypts a JSON string with AES-256-GCM, random 12-byte nonce. Output format: `base64(nonce).base64(ciphertext).base64(authTag)`.
  - `decrypt_aes(encrypted_payload, hex_key)` — Parses the 3-part format, recombines ciphertext + authTag, decrypts.
  - Key is accepted as a **hex-encoded** 32-byte string (64 hex characters).

- **`prover/src/api.rs`** (modified)
  - `/challenge` endpoint: Now accepts a raw encrypted string body (not JSON). Decrypts it to get `{ seed, session_id }`, processes, then encrypts the response `{ proof_bytes, seed, iteration }` before sending.
  - `/inclusion-proofs` endpoint: Same pattern — receives encrypted targets blob, decrypts to get `{ targets: [[block_id, position], ...] }`, generates Merkle proofs, encrypts the response.

- **`prover/src/main.rs`** — Added `mod crypto;` declaration.

- **`prover/Cargo.toml`** — Replaced `aes = "0.8"` + `cbc = "0.1"` with `aes-gcm = "0.10.3"`, added `base64 = "0.22"` and `hex = "0.4"`.

### Verifier side

- **`verifier/src/crypto.ts`** (new file, 50 lines)
  - `encryptAES(payload)` — Encrypts a JS object with AES-256-GCM using Node's `crypto` module. Same wire format as the Prover.
  - `decryptAES(encryptedPayload)` — Decrypts and JSON-parses.
  - Key loaded from `AES_SECRET_KEY` environment variable (hex-encoded).

- **`verifier/src/routes/challenge.ts`** (modified)
  - `POST /api/challenge/issue`: Now encrypts the challenge payload `{ seed, session_id }` and returns `{ sessionId, encryptedChallengeBlob }` instead of plaintext `{ sessionId, seed }`.
  - `POST /api/challenge/submit`: Now expects `{ sessionId, encryptedProofBlob }` instead of `{ sessionId, proofBytes, seed, iteration }`. Decrypts the blob server-side.
  - After decryption, uses `randomPathGenerator()` from native bindings to recreate the Prover's deterministic paths, samples 1% (minimum 1 target), encrypts the targets as `encryptedTargetsBlob`, and includes it in the response.

- **`verifier/src/routes/verify.ts`** (modified)
  - `POST /api/verify/inclusion`: Now expects `{ sessionId, encryptedInclusionBlob }` instead of plaintext proofs. Decrypts the blob to extract inclusion proofs.

### Proxy widget

- **`proxy/src/captcha-widget.ts`** and **`proxy/captcha-widget.js`** (modified)
  - Steps 4-7 of `startVerification()` were rewritten:
    - Step 4: Sends `challenge.encryptedChallengeBlob` as `text/plain` to the Prover (was JSON with plaintext seed).
    - Step 5: Reads response as raw text (`encryptedProofBlob`), forwards to Verifier (was JSON with `proof_bytes`, `seed`, `iteration`).
    - Step 6: Sends `submitResult.encryptedTargetsBlob` as `text/plain` to the Prover (was JSON with `targets` array that was always empty).
    - Step 7: Reads response as raw text (`encryptedInclusionBlob`), forwards to Verifier (was JSON with `inclusionData.proofs`).
  - The widget no longer sees any sensitive data (seeds, proof bytes, Merkle proofs). It only relays opaque encrypted strings.

---

## 4. Verification Logic Replaced (`541d9b8`)

### Before (mocked)

In `verifier/src/routes/verify.ts`, the cryptographic verification was stubbed:

```typescript
// TODO: In production, call Wasm verify_inclusion_proof() here
// For now, mark as valid if root hash matches commitment
valid = true;
reason = 'Root hash matches commitment (full Merkle verification pending Wasm integration)';
```

The time check was a simple inline comparison:

```typescript
const timeCheckPassed = elapsedMs < 2000;
```

### After (real)

- **Temporal check**: Calls native `verifyTimeBound(elapsedMs)` from the Rust binding.
- **Cryptographic check**: For each inclusion proof:
  1. Verifies `root_hash` matches the committed hash for that `block_id`
  2. Calls native `verifyInclusionProof(selfFragmentBuf, formattedSiblings, rootHashBuf)` to recompute the Merkle root from the leaf and sibling path, and compare against the expected root.
  3. Reason string changed to `'Verified securely via Native Rust binding'` on success.

### Target selection

- **Before**: The widget sent `submitResult.sampleTargets || []` (always empty — `sampleTargets` was never set).
- **After**: The Verifier uses `randomPathGenerator()` to regenerate all 70 paths, then randomly samples 1% (min 1) and sends them as an encrypted blob. The Prover can only see targets after decrypting.

---

## 5. JWT Token Hardening (`541d9b8`, `2f1f76d`)

### Token issuance (`verifier/src/session.ts`)

**Before:**
- Secret: hardcoded `'pos-captcha-secret-change-in-production'`
- Claims: `{ sessionId, clientId, verified, iat }`
- No unique token ID
- No algorithm specification
- No issuer/audience

**After:**
- Secret: loaded from `JWT_SECRET` env var; **throws on startup** if missing
- Claims: `{ jti, sessionId, clientId, verified, iat }` — `jti` is a UUID for unique identification
- Signing options: `{ expiresIn: '5m', issuer: 'pos-captcha-verifier', audience: 'pos-captcha-client', algorithm: 'HS256' }`

### Token verification

**Before:**
- `jwt.verify(token, JWT_SECRET)` with no options (accepts any algorithm)

**After:**
- Pinned to `{ algorithms: ['HS256'], issuer: 'pos-captcha-verifier', audience: 'pos-captcha-client' }` — rejects algorithm confusion attacks and tokens from other issuers
- **Stateful usage tracking**: Each token's `jti` is registered at issuance. `verifyToken()` increments a counter and rejects tokens used more than 5 times (`NB_MAX = 5`).

### Token endpoint (`verify.ts`)

**Before:**
```typescript
const decoded = require('jsonwebtoken').verify(token, process.env.JWT_SECRET || '...');
```

**After:**
```typescript
const decoded = verifyToken(token);
// Returns null if: invalid signature, expired, wrong issuer/audience, or usage limit exceeded
```

Error message updated: `'Invalid token, expired, or maximum usage limit reached.'`

---

## 6. AES Key Security (`2f1f76d`)

Removed all hardcoded cryptographic keys from the codebase.

### Prover (`prover/src/config.rs`)

- Added `aes_secret_key` field to `Config` struct with `#[serde(default)]`
- `Config::load()` now reads `AES_SECRET_KEY` env var (overrides config file)
- Panics on startup if the key is empty, still the old default `"pos-captcha-secret-key-32-bytes!"`, or not exactly 64 hex characters

### Prover (`prover/src/crypto.rs`)

- `encrypt_aes()` and `decrypt_aes()` now accept a **hex-encoded** key and decode it with `hex::decode()` before use
- Previously used `.as_bytes()` on a raw UTF-8 string (only worked if the string happened to be 32 ASCII chars)

### Verifier (`verifier/src/crypto.ts`)

- `loadAESKey()` reads `AES_SECRET_KEY` env var
- Validates it matches `/^[0-9a-fA-F]{64}$/` (64 hex chars = 32 bytes)
- Throws with a clear error message and generation instructions if missing or invalid
- No fallback value

### Config cleanup

- `prover/pos-config.json`: `aes_secret_key` field set to `""` (was `"pos-captcha-secret-key-32-bytes!"`)
- Added `.gitignore` with `.env` exclusion to prevent accidental secret commits

---

## 7. Minor Changes

- **`.gitignore`** (new file): Ignores `node_modules/`, `target/`, `target_cli/`, `dist/`, `*.node`, `.env`
- **`TECHNICAL_DOCS.md`**: Updated to reflect the new architecture (23 lines changed)
- **`prover/Cargo.lock`**: Updated with new dependency resolutions for `aes-gcm`, `base64`, `hex`

---

## Summary of What To Set Before Running

```bash
# Generate secrets (run once, save these values)
export AES_SECRET_KEY=$(openssl rand -hex 32)
export JWT_SECRET=$(openssl rand -hex 32)

# Both Prover and Verifier must share the same AES_SECRET_KEY.
# JWT_SECRET is only needed by the Verifier.
```

Without these env vars, both services will refuse to start with explicit error messages.
