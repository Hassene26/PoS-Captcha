/**
 * PoS-CAPTCHA Browser Extension — Background Service Worker
 *
 * Two responsibilities:
 *   1. Maintain the toolbar badge based on the prover's /status.
 *   2. Poll the prover's /pending-consent queue. When a request appears,
 *      either auto-respond using a previously remembered per-site decision
 *      or open a small consent popup window so the user can decide.
 */

const PROVER_URL = 'http://127.0.0.1:7331';
const CONSENT_POLL_MS = 1500;
const STATUS_POLL_MS = 10000;

// Track requests we've already started handling so we don't open a second
// window while the first is still up.
const inFlight = new Set();

// ---------- message bridge for popup.js ----------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_STATUS') {
    fetch(`${PROVER_URL}/status`, { signal: AbortSignal.timeout(2000) })
      .then(r => r.json())
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }
  if (message.type === 'CHECK_PROVER') {
    fetch(`${PROVER_URL}/status`, { signal: AbortSignal.timeout(2000) })
      .then(() => sendResponse({ online: true }))
      .catch(() => sendResponse({ online: false }));
    return true;
  }
  // The consent window asks us to deliver its decision back to the prover.
  if (message.type === 'CONSENT_DECISION') {
    submitDecision(message.requestId, message.allow, message.remember, message.siteId)
      .then(() => sendResponse({ ok: true }))
      .catch(err => sendResponse({ ok: false, error: err.message }));
    return true;
  }
});

// ---------- badge ---------------------------------------------------------

async function updateBadge() {
  try {
    const resp = await fetch(`${PROVER_URL}/status`, { signal: AbortSignal.timeout(2000) });
    const data = await resp.json();
    const state = (data.state || '').replace(/"/g, '');
    if (state === 'Ready') {
      chrome.action.setBadgeText({ text: '✓' });
      chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
    } else if (state === 'Plotting') {
      chrome.action.setBadgeText({ text: '...' });
      chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
    } else if (state === 'Proving') {
      chrome.action.setBadgeText({ text: '⚡' });
      chrome.action.setBadgeBackgroundColor({ color: '#3b82f6' });
    }
  } catch {
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
  }
}
setInterval(updateBadge, STATUS_POLL_MS);
updateBadge();

// ---------- consent ------------------------------------------------------

async function pollConsent() {
  let pending;
  try {
    const resp = await fetch(`${PROVER_URL}/pending-consent`, { signal: AbortSignal.timeout(2000) });
    if (!resp.ok) return;
    pending = await resp.json();
  } catch {
    return; // prover offline — nothing to do
  }

  // Reconcile: drop in-flight ids that the prover no longer reports as pending
  // (they've been resolved or timed out server-side). Without this, we'd never
  // be able to handle a *new* request from the same site again.
  const stillPending = new Set(pending.map(r => r.request_id));
  for (const id of inFlight) {
    if (!stillPending.has(id)) inFlight.delete(id);
  }

  for (const req of pending) {
    if (inFlight.has(req.request_id)) continue; // already showing a popup for it
    inFlight.add(req.request_id);
    // Note: we do NOT remove from inFlight when the popup opens. We only
    // remove via the reconcile loop above, once the prover confirms the
    // request is gone (decision submitted or 30 s timeout). This guarantees
    // exactly one popup per pending request.
    handleConsentRequest(req).catch(err => {
      console.error('[consent] handler error', err);
      inFlight.delete(req.request_id); // recover from a failed window open
    });
  }
}
setInterval(pollConsent, CONSENT_POLL_MS);

async function handleConsentRequest(req) {
  // Look up a remembered decision for this siteId.
  const remembered = await getRememberedDecision(req.site_id);
  if (remembered === 'allow' || remembered === 'deny') {
    await submitDecision(req.request_id, remembered === 'allow', false, req.site_id);
    return;
  }

  // Otherwise open the popup window. We pass request details via URL params.
  const params = new URLSearchParams({
    request_id: req.request_id,
    site_id: req.site_id,
  });
  const url = chrome.runtime.getURL(`consent.html?${params.toString()}`);

  await chrome.windows.create({
    url,
    type: 'popup',
    width: 420,
    height: 360,
    focused: true,
  });

  // Optional: a desktop notification in case the popup got hidden.
  try {
    chrome.notifications.create(req.request_id, {
      type: 'basic',
      iconUrl: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
      title: 'PoS-CAPTCHA authorization',
      message: `${req.site_id} wants to verify storage with your local plot.`,
      priority: 2,
    });
  } catch {}
}

async function submitDecision(requestId, allow, remember, siteId) {
  if (remember && siteId) {
    await rememberDecision(siteId, allow ? 'allow' : 'deny');
  }
  await fetch(`${PROVER_URL}/consent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_id: requestId, allow }),
  });
}

// ---------- per-site memory ---------------------------------------------

async function getRememberedDecision(siteId) {
  return new Promise(resolve => {
    chrome.storage.local.get(['posConsent'], result => {
      const map = result.posConsent || {};
      resolve(map[siteId]?.decision || null);
    });
  });
}

async function rememberDecision(siteId, decision) {
  return new Promise(resolve => {
    chrome.storage.local.get(['posConsent'], result => {
      const map = result.posConsent || {};
      map[siteId] = { decision, ts: Date.now() };
      chrome.storage.local.set({ posConsent: map }, resolve);
    });
  });
}
