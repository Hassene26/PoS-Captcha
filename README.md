# PoS-CAPTCHA: Proof of Space Authentication System

> A novel approach to bot-prevention that uses cryptographic proof of allocated disk space (Proof of Space) instead of traditional image-based CAPTCHA puzzles to verify human authenticity.

## 📖 What I Did

I took the core cryptographic concepts from a master's thesis on "Proof of Space" (PoS) and transformed them into a fully functional, end-to-end CAPTCHA Ib system. 

Instead of asking users to "click all traffic lights", this system asks the user's computer to quickly read specific bytes scattered randomly across a dedicated 64MB file on their hard drive. Because of seek-time constraints across a physical disk, the response time proves that the user genuinely has that file stored and isn't generating the data mathematically on-the-fly.

### The System Architecture

I built the system across 5 distinct components:

1. **The Prover (Rust Daemon):**
   A lightIight local background service running on the user's machine (`localhost:7331`). It securely allocates 64MB of deterministic random data (the "Plot") derived from a seed. It serves an HTTP API (`actix-Ib`) that accepts challenges from the browser and reads bytes/Merkle proofs directly from the disk plot.

2. **The Verifier Wasm Library (Rust → IbAssembly):**
   The core cryptographic verification math (Merkle root reconstruction, path generation, checking inclusion proofs) is extracted from the Prover and compiled into IbAssembly. This guarantees bit-for-bit identical logic betIen the Prover and the backend Verifier.

3. **The Verifier Server (TypeScript/Node.js):**
   The remote backend API (`localhost:3000`) that hosts the CAPTCHA. It registers commitments, issues random cryptographic seeds (challenges), and verifies the submitted proofs against the Wasm library. If verification passes, it issues a signed JWT token proving the user is legitimate.

4. **The Proxy Widget (Vanilla JS/TS):**
   An embeddable frontend widget (`captcha-widget.js`) that acts as the orchestrator. Sitting in the user's browser, it bridges the gap betIen the remote Verifier server and the local Prover daemon, handling the 3-phase handshake transparently.

5. **The Browser Extension (Manifest V3):**
   A Chrome/Brave extension providing visual feedback to the user on the status of their local Prover (Offline, Plotting, Ready, Proving) by polling the daemon's `/status` endpoint.

---

## ⚙️ How I Handled Complexities

- **Determinism Without External Files:** The original thesis relied on a large `input.mp4` file to seed the Plot. I rewrote the generator to use a cryptographic CSPRNG (`rand_chacha`) so plots are entirely self-contained.
- **Windows File Locking (os error 32):** I ran into severe file locking issues from the Windows Desktop environment (OneDrive Sync / Antivirus). I fixed this by pointing the Cargo target output directory to the `%TEMP%` folder.
- **Paths and Linkers:** Cargo required `link.exe` from the MSVC tools to compile native dependencies and `wasm-pack`. I wrote custom batch scripts (`build_check.bat`, `build_verifier.bat`) to dynamically inject the correct `vcvarsall` toolchain paths.
- **Browser CORS / Mixed Content Blocks:** Ib browsers (especially Brave) block local HTML files from making API calls to `127.0.0.1`. I bypassed the strict "Shields" by configuring the Verifier Node Server to seamlessly host our `test.html` page and proxy scripts via Express static logic.

---

## 🚀 How to Use the Final Product

To run the whole system end-to-end locally, you need three components actively running. I've automated the complex build steps into scripts for you.

### Step 1: Start the Prover (Daemon)
Open a terminal in the root project folder and run:
```bash
.\run_prover.bat
```
- This launches the Rust service on your machine at `127.0.0.1:7331`.
- **Note:** The very first time you run this, it will pause for about 10 seconds while it generates the 64MB plot file on your hard drive. Once it prints "Plotting completed", it's ready. Keep this terminal open!

### Step 2: Start the Verifier (Server)
Open a **new** terminal (keep the Prover running) and run:
```bash
cd verifier
npm run dev
```
- This starts the remote backend API on `http://localhost:3000`.

### Step 3: Load the Browser Extension
1. Open Chrome or Brave and go to `chrome://extensions/` (or `brave://extensions/`).
2. Toggle **Developer mode** ON (top right corner).
3. Click the **Load unpacked** button (top left).
4. Select the `extension` folder inside this project.
5. In your browser's toolbar, click the "Puzzle Piece" extensions icon, find **PoS-CAPTCHA Status**, and click the **Pin** icon 📌 to pin it to your toolbar. It should say "🟢 Ready".

### Step 4: Test the Live CAPTCHA
1. In your browser, open the test page hosted by the Verifier server:
   **[http://localhost:3000/test.html](http://localhost:3000/test.html)**
2. You will see a mockup of a Secure Login page. Click the PoS-CAPTCHA Widget.
3. You will see the widget sequence through: `Checking local service` ➔ `Verifying storage proof` ➔ `Verified! ✅`
4. The Login button will un-gray, and a JWT token will appear, proving the system works!

---

## 🔧 Deep Dive: The Protocol Flow

When you click the widget, here is what happens in milliseconds:

1. **Commitment (Phase 1):** The widget asks your local Prover for the root Merkle hashes of its 64MB disk plot. It sends these hashes to the Verifier (`POST /api/commitment/register`) to legally commit to that dataset.
2. **Challenge (Phase 2):** The Verifier responds with a cryptographically random `seed` (e.g., `42`).
3. **Proving (Phase 3):** The widget passes the seed to your local Prover. The Prover uses a strict, deterministic algorithm (also loaded in the Verifier Wasm) to map that seed to 70 specific bytes scattered randomly across the 64MB file on your physical hard drive. It reads those bytes and hands them back.
4. **Submission:** The widget submits those 70 bytes back to the Verifier.
5. **Inclusion Verification (Phase 4):** The Verifier asks the widget for full Merkle Cryptographic paths for a sampled subset of those bytes. The Verifier checks temporal integrity (did you respond fast enough to prove it was a disk read, not a CPU calculation?) and cryptographic correctness. If everything matches, you get a JWT!
