/**
 * PoS-CAPTCHA Browser Extension — Background Service Worker
 * 
 * Listens for messages from web pages (via the CAPTCHA widget) and
 * can relay status updates or coordinate with the popup.
 */

const PROVER_URL = 'http://127.0.0.1:7331';

// Listen for messages from content scripts or the popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_STATUS') {
    // Fetch prover status and return it
    fetch(`${PROVER_URL}/status`, {
      signal: AbortSignal.timeout(2000),
    })
      .then(resp => resp.json())
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    
    return true; // Keep the message channel open for async response
  }

  if (message.type === 'CHECK_PROVER') {
    // Simple health check
    fetch(`${PROVER_URL}/status`, {
      signal: AbortSignal.timeout(2000),
    })
      .then(() => sendResponse({ online: true }))
      .catch(() => sendResponse({ online: false }));
    
    return true;
  }
});

// Update badge based on prover status
async function updateBadge() {
  try {
    const resp = await fetch(`${PROVER_URL}/status`, {
      signal: AbortSignal.timeout(2000),
    });
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

// Poll every 10 seconds for badge updates
setInterval(updateBadge, 10000);
updateBadge();
