/* Qualys DA - Core JavaScript */

// ── Theme Toggle ──────────────────────────────────────────────
function initTheme() {
    const saved = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
}

initTheme();

// ── API Helper ────────────────────────────────────────────────
async function fetchApi(url, options = {}) {
    try {
        const resp = await fetch(url, options);
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ error: resp.statusText }));
            showToast(err.error || 'Request failed: ' + resp.status, 'error');
            return null;
        }
        return await resp.json();
    } catch (e) {
        showToast('Network error: ' + e.message, 'error');
        return null;
    }
}

// ── DOM Helpers ───────────────────────────────────────────────
function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function setHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}

// ── Toast Notifications ──────────────────────────────────────
let toastTimeout = null;

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.textContent = message;
    container.appendChild(toast);

    // Trigger animation
    requestAnimationFrame(() => toast.classList.add('show'));

    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ── Connection Status ────────────────────────────────────────
//
// The dot reads /api/health-status (a single DB read of the latest
// `health_log` row written by the in-process heartbeat job, default 4h
// cadence). We deliberately do NOT hit /api/health on every page load —
// that would trigger a fresh Qualys auth call every navigation, burning
// tokens and quota on a tenant with tight rate limits.
//
// Colour scheme:
//   green  — both VM + CSAM up, heartbeat fresh
//   amber  — heartbeat is stale (scheduler may have died)
//   red    — either API was down on the latest heartbeat
//   grey   — no heartbeat yet (first 30s after app start)
//
// Toasts fire on transitions so an operator already on the page sees
// failures even if they don't notice the dot colour change.

let _lastHealthState = null;  // 'ok' | 'fail' | 'stale' | 'pending'
let _lastHealthAnnouncedFail = false;  // dedup repeat-failure toasts

function _humanAge(seconds) {
    if (seconds == null) return 'never';
    if (seconds < 60) return seconds + 's ago';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
    return Math.floor(seconds / 86400) + 'd ago';
}

async function checkConnection() {
    const dot = document.getElementById('connection-dot');
    if (!dot) return;
    try {
        const resp = await fetch('/api/health-status', { method: 'GET' });
        if (!resp.ok) {
            dot.className = 'status-dot status-error';
            dot.title = `Heartbeat endpoint returned ${resp.status}`;
            return;
        }
        const data = await resp.json();

        let state, klass, tooltip;
        if (data.checked_at == null) {
            state = 'pending';
            klass = 'status-pending';
            tooltip = 'Awaiting first heartbeat...';
        } else if (data.vm === false || data.csam === false) {
            state = 'fail';
            klass = 'status-error';
            const parts = [`Last checked: ${_humanAge(data.age_seconds)}`];
            parts.push(`VM ${data.vm ? '✓' : '✗'}`);
            parts.push(`CSAM ${data.csam ? '✓' : '✗'}`);
            const errs = [];
            if (data.vm_error) errs.push(`VM: ${data.vm_error.slice(0, 80)}`);
            if (data.csam_error) errs.push(`CSAM: ${data.csam_error.slice(0, 80)}`);
            tooltip = parts.join(' · ') + (errs.length ? '\n' + errs.join('\n') : '');
        } else if (data.stale) {
            state = 'stale';
            klass = 'status-warn';
            tooltip = `Heartbeat stale — last checked ${_humanAge(data.age_seconds)}.\nScheduler may have stopped firing.`;
        } else {
            state = 'ok';
            klass = 'status-ok';
            tooltip = `Last checked: ${_humanAge(data.age_seconds)} — VM ✓, CSAM ✓`;
        }
        dot.className = 'status-dot ' + klass;
        dot.title = tooltip;

        // Toast on transitions only — not on every poll.
        if (state === 'fail' && !_lastHealthAnnouncedFail) {
            const which = !data.vm ? 'VM' : 'CSAM';
            const errMsg = (data.vm_error || data.csam_error || '').slice(0, 120);
            showToast(`Qualys ${which} unreachable — ${errMsg}`, 'error');
            _lastHealthAnnouncedFail = true;
        } else if (state === 'ok' && _lastHealthAnnouncedFail) {
            showToast('Qualys connectivity restored', 'success');
            _lastHealthAnnouncedFail = false;
        }
        _lastHealthState = state;
    } catch (e) {
        dot.className = 'status-dot status-error';
        dot.title = 'Cannot reach app: ' + e.message;
    }
}

// ── Asset-Count Chip ─────────────────────────────────────────
//
// Always-visible "look under the hood" indicator showing CSAM / VM Hosts /
// VM Detections row counts (compact format: "85k · 9.5k · 62k"). Hover for
// full numbers + last-refresh age. Click to open Data Explorer. Folded into
// the same 60s poller as the connection dot to avoid a second timer.

function _fmtCompact(n) {
    if (n == null) return '0';
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 10000) return Math.floor(n / 1000) + 'k';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
    return String(n);
}

async function loadAssetCounter() {
    const el = document.getElementById('asset-counter');
    if (!el) return;
    try {
        const resp = await fetch('/api/ingestion-stats');
        if (!resp.ok) return;
        const d = await resp.json();
        const csam = d.csam_assets_count || 0;
        const hosts = d.vm_hosts_count || 0;
        const dets = d.vm_detections_count || 0;
        el.textContent = `${_fmtCompact(csam)} · ${_fmtCompact(hosts)} · ${_fmtCompact(dets)}`;
        const isEmpty = (csam + hosts + dets) === 0;
        el.classList.toggle('asset-counter-empty', isEmpty);
        const tooltip = [
            `CSAM ${csam.toLocaleString()} · Hosts ${hosts.toLocaleString()} · Detections ${dets.toLocaleString()}`,
            d.last_success ? `Last successful refresh: ${d.last_success}` : 'No successful refresh yet',
            'Click to open Data Explorer',
        ].join('\n');
        el.title = tooltip;
    } catch (e) {
        // Non-fatal — leave the chip alone if the endpoint is down.
    }
}

function _heartbeatTick() {
    checkConnection();
    loadAssetCounter();
}

// Initial render + 60s poll cycle for both the dot and the chip.
_heartbeatTick();
setInterval(_heartbeatTick, 60000);

// ── Refresh-in-progress Banner ───────────────────────────────
// Polls /api/refresh-status every 3s. When a pull is running, shows
// live per-API progress. When one flips to terminal, shows the final
// per-API outcome for 8s before hiding — so the operator never stares
// at a stale dashboard wondering whether the last Refresh click took.
function fmtApiBadge(label, status, count, expected) {
    const icon = (status === 'success') ? '&#10003;'
               : (status === 'partial') ? '&#9888;'
               : (status === 'failed')  ? '&#10007;'
               : '&middot;';
    const countStr = (count != null)
        ? (expected ? `${formatNumber(count)}/${formatNumber(expected)}`
                    : formatNumber(count))
        : '--';
    return `<span class="refresh-api refresh-api-${status || 'pending'}">${icon} ${label} ${countStr}</span>`;
}

async function pollRefreshStatus() {
    const banner = document.getElementById('refresh-banner');
    const txt = document.getElementById('refresh-banner-text');
    if (!banner || !txt) return;

    let row;
    try {
        const resp = await fetch('/api/refresh-status');
        if (!resp.ok) return;
        row = await resp.json();
    } catch { return; }

    if (!row) {
        banner.style.display = 'none';
        banner.className = 'refresh-banner';
        return;
    }

    const running = row.status === 'running';
    const badges = [
        fmtApiBadge('CSAM', running ? 'pending' : row.csam_status,
                    row.csam_count, row.csam_expected),
        fmtApiBadge('Hosts', running ? 'pending' : row.vm_host_status,
                    row.vm_host_count, row.vm_host_expected),
        fmtApiBadge('Detections', running ? 'pending' : row.vm_detection_status,
                    row.vm_detection_count, row.vm_detection_expected),
    ].join(' · ');

    const prefix = running
        ? 'Refresh in progress — showing last snapshot'
        : (row.status === 'partial'
           ? 'Refresh completed with partial data'
           : (row.status === 'failed' ? 'Refresh failed' : 'Refresh complete'));
    txt.innerHTML = `<strong>${prefix}</strong> · ${badges}`;

    banner.className = 'refresh-banner refresh-banner-' + (row.status || 'running');
    banner.style.display = '';
}

pollRefreshStatus();
setInterval(pollRefreshStatus, 3000);

// ── Active Nav Highlight ─────────────────────────────────────
function highlightNav() {
    const path = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        const href = link.getAttribute('href');
        if (href === path || (href !== '/' && path.startsWith(href))) {
            link.classList.add('active');
        }
    });
}

highlightNav();

// ── Number Formatting ────────────────────────────────────────
function formatNumber(n) {
    if (n === null || n === undefined) return '--';
    return Number(n).toLocaleString();
}

function formatPct(n) {
    if (n === null || n === undefined) return '--';
    return Number(n).toFixed(1) + '%';
}

// ── Chart Color Palette ──────────────────────────────────────
const chartColors = {
    severity: {
        1: '#94a3b8',
        2: '#3b82f6',
        3: '#f59e0b',
        4: '#ea580c',
        5: '#ef4444'
    },
    status: {
        'New': '#3b82f6',
        'Active': '#f59e0b',
        'Fixed': '#10b981',
        'Re-Opened': '#ef4444'
    },
    palette: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16']
};

// ── Chart.js Defaults ────────────────────────────────────────
if (typeof Chart !== 'undefined') {
    Chart.defaults.color = getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim() || '#94a3b8';
    Chart.defaults.borderColor = getComputedStyle(document.documentElement).getPropertyValue('--border-color').trim() || '#334155';
    Chart.defaults.font.family = "'Inter', -apple-system, sans-serif";
}
