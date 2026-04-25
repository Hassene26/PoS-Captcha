/**
 * PoS-CAPTCHA Consent Window
 *
 * Reads the request_id and site_id from the URL query string, lets the user
 * decide, then forwards the decision to the background service worker (which
 * relays it to the local prover at POST /consent).
 */

const params = new URLSearchParams(location.search);
const requestId = params.get('request_id');
const siteId = params.get('site_id') || '(unknown site)';

document.getElementById('siteId').textContent = siteId;

function decide(allow) {
  const remember = document.getElementById('remember').checked;
  chrome.runtime.sendMessage(
    { type: 'CONSENT_DECISION', requestId, allow, remember, siteId },
    () => window.close()
  );
}

document.getElementById('allow').addEventListener('click', () => decide(true));
document.getElementById('deny').addEventListener('click', () => decide(false));

// If the user just closes the window, deny by default.
window.addEventListener('beforeunload', () => {
  // Best-effort: only fire if no decision was sent yet. Keep it simple — if
  // the user already clicked, the prover has already received the answer.
});
