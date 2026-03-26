/**
 * PoS-CAPTCHA Browser Extension — Popup Script
 * 
 * Polls the local Prover's /status endpoint and updates the UI.
 */

const PROVER_URL = 'http://127.0.0.1:7331';
const POLL_INTERVAL_MS = 3000;

const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const diskUsed = document.getElementById('diskUsed');
const blockGroups = document.getElementById('blockGroups');
const progressBar = document.getElementById('progressBar');
const progressFill = document.getElementById('progressFill');

const STATE_MAP = {
  'Ready':    { class: 'ready',    label: '🟢 Ready' },
  'Plotting': { class: 'plotting', label: '🟡 Plotting...' },
  'Proving':  { class: 'proving',  label: '🔵 Proving...' },
  'Error':    { class: 'error',    label: '🔴 Error' },
};

async function pollStatus() {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    const response = await fetch(`${PROVER_URL}/status`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) throw new Error('Bad response');

    const data = await response.json();
    updateUI(data);

  } catch (err) {
    // Service is offline
    setOffline();
  }
}

function updateUI(data) {
  const stateName = data.state.replace(/"/g, '');
  const stateInfo = STATE_MAP[stateName] || STATE_MAP['Error'];

  // Update status indicator
  statusDot.className = `status-dot ${stateInfo.class}`;
  statusText.className = `status-text ${stateInfo.class}`;
  statusText.textContent = stateInfo.label;

  // Update info grid
  diskUsed.textContent = `${data.disk_used_mb || 0} MB`;
  blockGroups.textContent = `${data.num_block_groups || 0}`;

  // Show progress bar during plotting
  if (stateName === 'Plotting') {
    progressBar.style.display = 'block';
    progressFill.style.width = `${data.plot_progress || 0}%`;
  } else {
    progressBar.style.display = 'none';
  }
}

function setOffline() {
  statusDot.className = 'status-dot offline';
  statusText.className = 'status-text offline';
  statusText.textContent = '🔴 Offline';
  diskUsed.textContent = '—';
  blockGroups.textContent = '—';
  progressBar.style.display = 'none';
}

// Initial poll + periodic polling
pollStatus();
setInterval(pollStatus, POLL_INTERVAL_MS);
