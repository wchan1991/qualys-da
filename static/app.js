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
async function checkConnection() {
    const dot = document.getElementById('connection-dot');
    if (!dot) return;
    try {
        const resp = await fetch('/api/health', { method: 'GET' });
        dot.className = 'status-dot ' + (resp.ok ? 'status-ok' : 'status-warn');
        dot.title = resp.ok ? 'Connected' : 'API issues';
    } catch {
        dot.className = 'status-dot status-error';
        dot.title = 'Disconnected';
    }
}

// Check connection on load, then every 60 seconds
checkConnection();
setInterval(checkConnection, 60000);

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
