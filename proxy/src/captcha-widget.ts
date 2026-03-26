/**
 * PoS-CAPTCHA Proxy Widget
 * 
 * Embeddable script that orchestrates the challenge-response flow
 * between the remote Verifier server and the local Prover daemon.
 * 
 * Usage:
 *   <div id="pos-captcha"></div>
 *   <script src="captcha-widget.js"></script>
 *   <script>
 *     PoSCaptcha.init({
 *       element: '#pos-captcha',
 *       verifierUrl: 'http://localhost:3000',
 *       proverUrl: 'http://127.0.0.1:7331',
 *       clientId: 'user-123',
 *       onSuccess: (token) => console.log('Verified!', token),
 *       onError: (err) => console.error('Failed:', err),
 *     });
 *   </script>
 */

interface PoSCaptchaConfig {
  element: string | HTMLElement;
  verifierUrl: string;
  proverUrl: string;
  clientId: string;
  onSuccess?: (token: string) => void;
  onError?: (error: string) => void;
}

interface ProverStatus {
  state: string;
  disk_used_mb: number;
  plot_progress: number;
  num_block_groups: number;
}

const PoSCaptcha = {
  config: null as PoSCaptchaConfig | null,
  container: null as HTMLElement | null,

  init(config: PoSCaptchaConfig) {
    this.config = config;

    // Resolve container element
    if (typeof config.element === 'string') {
      this.container = document.querySelector(config.element);
    } else {
      this.container = config.element;
    }

    if (!this.container) {
      console.error('[PoS-CAPTCHA] Container element not found');
      return;
    }

    this.render('idle');
    this.checkProverStatus();
  },

  render(state: 'idle' | 'checking' | 'proving' | 'success' | 'error' | 'offline', message?: string) {
    if (!this.container) return;

    const stateConfig: Record<string, { icon: string; text: string; color: string }> = {
      idle: { icon: '🔒', text: 'Click to verify storage', color: '#6366f1' },
      checking: { icon: '🔍', text: 'Checking local service...', color: '#f59e0b' },
      proving: { icon: '⏳', text: 'Verifying storage proof...', color: '#3b82f6' },
      success: { icon: '✅', text: 'Verified!', color: '#10b981' },
      error: { icon: '❌', text: message || 'Verification failed', color: '#ef4444' },
      offline: { icon: '🔴', text: 'Local service offline', color: '#6b7280' },
    };

    const s = stateConfig[state];

    this.container.innerHTML = `
      <div style="
        display: flex; align-items: center; gap: 12px;
        padding: 12px 20px; border-radius: 8px;
        border: 2px solid ${s.color}22;
        background: ${s.color}08;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        cursor: ${state === 'idle' || state === 'offline' ? 'pointer' : 'default'};
        transition: all 0.2s;
        user-select: none;
      " id="pos-captcha-btn">
        <span style="font-size: 24px;">${s.icon}</span>
        <div>
          <div style="font-size: 14px; font-weight: 600; color: ${s.color};">${s.text}</div>
          <div style="font-size: 11px; color: #888; margin-top: 2px;">PoS-CAPTCHA</div>
        </div>
      </div>
    `;

    const btn = this.container.querySelector('#pos-captcha-btn') as HTMLElement;
    if (btn && (state === 'idle' || state === 'offline')) {
      btn.addEventListener('click', () => this.startVerification());
    }
  },

  async checkProverStatus(): Promise<ProverStatus | null> {
    try {
      const resp = await fetch(`${this.config!.proverUrl}/status`, {
        signal: AbortSignal.timeout(2000),
      });
      const status: ProverStatus = await resp.json();

      if (status.state === 'Ready') {
        this.render('idle');
      } else if (status.state === 'Plotting') {
        this.render('checking', `Plotting: ${status.plot_progress}%`);
      }

      return status;
    } catch {
      this.render('offline');
      return null;
    }
  },

  async startVerification() {
    if (!this.config) return;
    const { verifierUrl, proverUrl, clientId, onSuccess, onError } = this.config;

    try {
      // Step 1: Check if prover is online
      this.render('checking');
      const status = await this.checkProverStatus();
      if (!status || status.state !== 'Ready') {
        this.render('offline');
        onError?.('Local PoS service is not running');
        return;
      }

      // Step 2: Ensure commitment is registered
      this.render('proving');
      const commitResp = await fetch(`${verifierUrl}/api/commitment/${clientId}`);
      if (!commitResp.ok) {
        // Need to register commitment first
        const proverCommitment = await fetch(`${proverUrl}/commitment`);
        const commitData = await proverCommitment.json();

        // Convert root hashes to hex
        const rootHashesHex = commitData.root_hashes.map((hash: number[]) =>
          hash.map((b: number) => b.toString(16).padStart(2, '0')).join('')
        );

        await fetch(`${verifierUrl}/api/commitment/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            clientId,
            rootHashes: rootHashesHex,
            numBlockGroups: commitData.num_block_groups,
          }),
        });
      }

      // Step 3: Request challenge from Verifier
      const challengeResp = await fetch(`${verifierUrl}/api/challenge/issue`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientId }),
      });
      const challenge = await challengeResp.json();

      // Step 4: Forward challenge to local Prover
      const proofResp = await fetch(`${proverUrl}/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          seed: challenge.seed,
          session_id: challenge.sessionId,
        }),
      });
      const proofData = await proofResp.json();

      // Step 5: Submit proof to Verifier
      const submitResp = await fetch(`${verifierUrl}/api/challenge/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: challenge.sessionId,
          proofBytes: proofData.proof_bytes,
          seed: proofData.seed,
          iteration: proofData.iteration,
        }),
      });
      const submitResult = await submitResp.json();

      // Step 6: Request and submit inclusion proofs
      // The Verifier needs inclusion proofs for a sample of the submitted bytes
      // For now, request proofs for a few random (block_id, position) pairs
      const inclusionResp = await fetch(`${proverUrl}/inclusion-proofs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targets: submitResult.sampleTargets || [], // The verifier would tell us which to prove
        }),
      });
      const inclusionData = await inclusionResp.json();

      // Step 7: Submit inclusion proofs for final verification
      const verifyResp = await fetch(`${verifierUrl}/api/verify/inclusion`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: challenge.sessionId,
          inclusionProofs: inclusionData.proofs || [],
        }),
      });
      const verifyResult = await verifyResp.json();

      if (verifyResult.status === 'passed' && verifyResult.token) {
        this.render('success');
        onSuccess?.(verifyResult.token);
      } else {
        this.render('error', verifyResult.message || 'Verification failed');
        onError?.(verifyResult.message || 'Verification failed');
      }

    } catch (err: any) {
      this.render('error', err.message || 'Unknown error');
      onError?.(err.message || 'Unknown error');
    }
  },
};

// Export for use in script tags
(window as any).PoSCaptcha = PoSCaptcha;
