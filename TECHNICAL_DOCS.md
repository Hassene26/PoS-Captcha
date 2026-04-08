# Technical Documentation & Codebase Breakdown

This document provides a detailed breakdown of the codebase, explaining what every part of the code does, mapping the main features highlighted in the README, and documenting the origin of each file (whether it was kept from the original Master's Thesis, modified, or created entirely from scratch).

---

## 🏗️ 1. The Prover Daemon (`/prover`)
*Written in Rust.* The local daemon running on the user's physical machine. It handles allocating the actual 64MB of disk space and responding to intense read-challenges.

### Core Cryptographic Math (Ported from Thesis)
These files contain the highly optimized, memory-hard mathematical logic that guarantees the user actually has to allocate physical disk space.
- **`src/block_generation/blockgen.rs` [KEPT]**: The heart of the Proof of Space algorithm. Uses AVX2 SIMD instructions to quickly generate complex byte arrays that are mathematically expensive to reconstruct on-the-fly.
- **`src/block_generation/utils.rs` [MODIFIED]**: Contains the physical constants of the system (e.g., `NUM_BYTES_IN_BLOCK_GROUP = 2 MiB`, `BATCH_SIZE = 70`). We modified it to allow dynamic plot sizes instead of hardcoded numbers.
- **`src/merkle_tree/structs.rs` & `client_verify.rs` [MODIFIED]**: Standard Merkle Tree logic used to prove that a specific block of data belongs to the 64MB plot the user committed to. We added JSON serialization tags so these structs could be sent over HTTP.
- **`src/communication/path_generator.rs` [MODIFIED]**: The crucial deterministic `random_path_generator`. When given a random `seed` by the Verifier, it spits out 70 exact `(block_id, byte_position)` pairs. Both the Prover and Verifier must run this exact identical function.

### Disk Plotting (New Logic)
The original thesis required the user to have an `input.mp4` file to seed the generation. We removed this requirement.
- **`src/block_generation/encoder.rs` [MODIFIED heavily]**: We stripped out the file-reading logic and adjusted the `encode` function to accept raw memory buffers initialized by a cryptographic RNG.
- **`src/plotter.rs` [NEW]**: Orchestrates the storage allocation. If no `output.bin` plot exists on disk, it uses `rand_chacha` (a CSPRNG) to generate 64MB of random bytes, feeds them through the `encoder.rs`, writes the final Proof of Space plot to disk, and saves the 32 Merkle root hashes (`root_hashes.bin`).

### API & Server Infrastructure (New Logic)
The original thesis used raw TCP sockets to communicate between Prover and Verifier threads. Because we needed to integrate this into a web browser, we had to replace TCP with HTTP.
- **`src/api.rs` [NEW]**: Defines the `actix-web` HTTP endpoints:
  - `GET /status`: Returns whether the Prover is Ready, Plotting, or Offline.
  - `GET /commitment`: Returns the 32 Merkle root hashes for Phase 1.
  - `POST /challenge`: Accepts the random seed, uses `path_generator` to find the 70 bytes on disk, reads them out of `output.bin`, and returns them.
  - `POST /inclusion-proofs`: Serves the cryptographic Merkle proofs for the Verifier's sample check.
- **`src/communication/structs.rs` [NEW]**: Defines the JSON HTTP schemas for all the requests and responses in `api.rs`.
- **`src/main.rs` & `src/config.rs` [NEW]**: Bootstraps the local HTTP server, handles permissive CORS (so the proxy widget can fetch from `127.0.0.1`), and loads configuration (`pos-config.json`).

---

## 🛡️ 2. The Verifier Native Bindings (`/verifier/native`)
*Written in Rust, compiled via NAPI-RS to a Node.js C++ Addon.* 
Because the Prover is computing complex Merkle tree hashes and deterministic paths (`path_generator.rs`), the Node.js Verifier Backend must run the **exact** same logic to check the answers. Re-writing complex cryptographic byte-math in TypeScript is highly prone to subtle bugs.
- **`native/src/lib.rs` [NEW]**: We ported the crucial `path_generator` and `merkle_tree` math directly from the Prover into this new Rust library. We then wrap it using `@napi-rs`, which allows Node.js to call these Rust functions synchronously and natively. It exports `verify_inclusion_proof()`, ensuring parity between client and server without WebAssembly overhead.

---

## 🌐 3. The Verifier Node.js Backend (`/verifier`)
*Written in TypeScript (Express.js).* 
This is the remote server that acts as the "Referee" for the CAPTCHA.
- **`src/server.ts` [NEW]**: The Express application entry point. We added static hosting here to bypass Brave's strict CORS rules for local HTML testing.
- **`src/crypto.ts` [NEW]**: Handlers AES encryption/decryption matching the Prover's implementation. Implements End-to-End AES-256-GCM encryption for payload transmission with the verifier, stopping man-in-the-middle reads.
- **`src/session.ts` [NEW]**: A simple in-memory session store. It maps a `clientId` to their committed 64MB plot (Phase 1), tracks when a challenge is issued, and issues JWT (JSON Web Tokens) with a `NB_MAX` usage limit and TTL when a user passes Phase 4.
- **`src/routes/commitment.ts` [NEW]**: Handles `POST /api/commitment/register`, saving the user's 32 Merkle root hashes to the server's memory.
- **`src/routes/challenge.ts` [NEW]**: 
  - `POST /issue`: Generates the random cryptographic `seed` (e.g., 42), encrypts it via AES, and sends it to the proxy.
  - `POST /submit`: Accepts the AES-encrypted proof bytes, decrypts them, and timestamps the response to measure disk-read speed.
- **`src/routes/verify.ts` [NEW]**: Handles `POST /verify/inclusion`. This is the final referee. It first checks **Temporal Integrity** (using native Rust bindings). Then it checks **Cryptographic Correctness** (do the inclusion proofs match the committed root hashes? Checked securely inside native Rust).

---

## 🧩 4. The Proxy Widget (`/proxy`)
*Written in TypeScript, compiled to Vanilla JS.* 
This script sits inside the website you are trying to log into (e.g., `test.html`).
- **`src/captcha-widget.ts` [NEW]**: The orchestrator. It acts as a blind proxy because the Verifier Server (`node`) cannot talk to the Prover (`127.0.0.1:7331`) natively across the internet. 
  1. It pings the Prover to check if it's running.
  2. It fetches the commitment from the Prover and sends it to the Verifier.
  3. It fetches the AES-encrypted challenge from the Verifier and blindly forwards it to the Prover.
  4. It fetches the AES-encrypted proof blob from the Prover and forwards it back to the Verifier.
  5. It handles the UI state.

---

## 🧩 5. The Browser Extension (`/extension`)
*Written in HTML/JS (Manifest V3).* 
Because the Prover is a background daemon with no GUI, the user needs to know what it is doing.
- **`manifest.json` [NEW]**: Sets up the permission to poll `http://127.0.0.1:7331/*`.
- **`popup.js` & `popup.html` [NEW]**: Creates the dark-themed dropdown UI. It runs a `setInterval` loop every 3 seconds to fetch the `/status` endpoint from the Prover, parsing it to update the color dots (🔴 Offline, 🟡 Plotting, 🔵 Proving, 🟢 Ready).
- **`background.js` [NEW]**: A service worker that runs even when the popup is closed. It polls the Prover every 10 seconds simply to update the tiny colored badge on the extension icon in standard Chrome toolbars.
