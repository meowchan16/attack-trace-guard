/**
 * The Agency — Boutique Cybersecurity Agency Dashboard
 * Client-side script:
 * - Date formatting & agent profile loading
 * - Accordion interactions & Back Issues
 * - WebSocket client with auto-reconnect (2s backing off to 10s)
 * - Real-time Chart.js line chart with dynamic color shifting
 * - Attack simulation trigger (/api/attack) with selectable vectors
 * - Case File dossier: WHEN, WHERE (SVG World Map), HOW (Timeline)
 * - Network Topology SVG with BFS vs A* AI route tracing & speedup metrics
 * - Real-time Watchlist table with interactive map highlighting
 */

document.addEventListener('DOMContentLoaded', () => {
  initLiveDates();
  initDashboardProfile();
  initAccordions();
  initTelemetryWebSocket();
  initAttackButton();
  initResetButton();
  initAutoDemoSwitch();
  initReconnectListeners();
  loadBackIssues();
  loadWatchlist();
});

/**
 * Utility to escape HTML entities
 */
function escapeHtml(text) {
  if (text === null || text === undefined) return '';
  const div = document.createElement('div');
  div.textContent = String(text);
  return div.innerHTML;
}

/**
 * Format and populate current date strings in all designated elements
 */
function initLiveDates() {
  const now = new Date();

  // Long editorial date format: "Sunday, October 18, 2026"
  const longFormatter = new Intl.DateTimeFormat('en-US', {
    weekday: 'long',
    month: 'long',
    day: 'numeric',
    year: 'numeric'
  });

  // Short format: "Oct 18, 2026"
  const shortFormatter = new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  });

  const formattedLong = longFormatter.format(now);
  const formattedShort = shortFormatter.format(now);

  const loginDateEl = document.getElementById('today-date-login');
  if (loginDateEl) loginDateEl.textContent = formattedShort;

  const dashboardHeroDateEl = document.getElementById('today-date-dashboard');
  if (dashboardHeroDateEl) dashboardHeroDateEl.textContent = formattedLong;
}

/**
 * Fetch authenticated user profile via /api/me and update hero elements
 */
async function initDashboardProfile() {
  const displayNameEl = document.getElementById('agent-display-name');
  const monogramEl = document.getElementById('agent-monogram');

  if (!displayNameEl) return;

  try {
    const res = await fetch('/api/me', {
      headers: { 'Accept': 'application/json' }
    });

    if (res.status === 401) {
      window.location.href = '/login';
      return;
    }

    if (res.ok) {
      const data = await res.json();
      if (data && data.display_name) {
        displayNameEl.textContent = data.display_name;

        if (monogramEl) {
          const parts = data.display_name.trim().split(/\s+/);
          let monogram = '';
          if (parts.length >= 2) {
            monogram = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
          } else if (parts.length === 1 && parts[0].length > 0) {
            monogram = parts[0].substring(0, 2).toUpperCase();
          } else {
            monogram = 'AG';
          }
          monogramEl.textContent = monogram;
        }
      }
    }
  } catch (err) {
    console.error('[The Agency] Failed to fetch agent profile:', err);
  }
}

/**
 * Back Issues Accordion toggle handler
 */
function initAccordions() {
  const accordionButtons = document.querySelectorAll('.accordion-trigger');

  accordionButtons.forEach(btn => {
    btn.onclick = () => {
      const isExpanded = btn.getAttribute('aria-expanded') === 'true';
      const targetId = btn.getAttribute('aria-controls');
      const targetContent = document.getElementById(targetId);

      if (!targetContent) return;

      if (isExpanded) {
        btn.setAttribute('aria-expanded', 'false');
        targetContent.classList.remove('is-open');
      } else {
        btn.setAttribute('aria-expanded', 'true');
        targetContent.classList.add('is-open');
      }
    };
  });
}

/**
 * ============================================================================
 * Attack Trigger & Demo Reset Handlers
 * ============================================================================
 */

function initAttackButton() {
  const attackBtn = document.getElementById('launch-attack-btn');
  const typeSelect = document.getElementById('attack-type-select');
  if (!attackBtn) return;

  attackBtn.addEventListener('click', async () => {
    if (attackBtn.disabled) return;
    attackBtn.disabled = true;

    const selectedType = typeSelect ? typeSelect.value : 'random';

    try {
      const res = await fetch('/api/attack', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ type: selectedType })
      });

      if (res.status === 409) {
        // Attack already in progress
        attackBtn.disabled = true;
      } else if (!res.ok) {
        attackBtn.disabled = false;
      }
    } catch (_) {
      attackBtn.disabled = false;
    }
  });
}

function initResetButton() {
  const resetBtn = document.getElementById('reset-demo-btn');
  if (!resetBtn) return;

  resetBtn.addEventListener('click', async () => {
    if (resetBtn.disabled) return;
    resetBtn.disabled = true;

    try {
      await fetch('/api/reset', {
        method: 'POST',
        headers: { 'Accept': 'application/json' }
      });
    } catch (_) {
      // Quiet recovery
    } finally {
      resetBtn.disabled = false;
    }
  });
}

/**
 * 60-Second Auto-demo Switch Handler
 */
let autoDemoInterval = null;

function initAutoDemoSwitch() {
  const switchEl = document.getElementById('auto-demo-switch');
  if (!switchEl) return;

  switchEl.addEventListener('change', () => {
    if (switchEl.checked) {
      startAutoDemo();
    } else {
      stopAutoDemo();
    }
  });
}

function startAutoDemo() {
  stopAutoDemo();
  autoDemoInterval = setInterval(() => {
    if (!isAttackActive) {
      const attackBtn = document.getElementById('launch-attack-btn');
      if (attackBtn && !attackBtn.disabled) {
        attackBtn.click();
      }
    }
  }, 60000);
}

function stopAutoDemo() {
  if (autoDemoInterval) {
    clearInterval(autoDemoInterval);
    autoDemoInterval = null;
  }
}

/**
 * Fetch past incidents from /api/incidents and render the Back Issues accordion
 */
async function loadBackIssues() {
  const listEl = document.getElementById('back-issues-list');
  if (!listEl) return;

  try {
    const res = await fetch('/api/incidents', {
      headers: { 'Accept': 'application/json' }
    });
    if (!res.ok) {
      listEl.innerHTML = '<li class="back-issues-placeholder">Unable to retrieve back issues at this time. Our records remain secure.</li>';
      return;
    }

    const incidents = await res.json();
    if (!Array.isArray(incidents) || incidents.length === 0) {
      listEl.innerHTML = '<li class="back-issues-empty">No back issues yet.</li>';
      return;
    }

    listEl.innerHTML = incidents.map((inc, idx) => {
      const num = String(idx + 1).padStart(2, '0');
      let dateStr = '';
      if (inc.ts) {
        try {
          const d = new Date(inc.ts);
          dateStr = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        } catch (_) {
          dateStr = inc.ts;
        }
      }

      const probVal = inc.probability !== undefined ? inc.probability : 0.95;
      const probPct = Math.round(probVal * 100);
      const isTerracotta = probPct >= 80;
      const probTagClass = isTerracotta ? 'pill-tag-terracotta' : 'pill-tag-olive';

      const reportText = inc.report && inc.report.body ? inc.report.body : '';
      const planSteps = (inc.plan && inc.plan.steps) ? inc.plan.steps : [];
      const planStepsHtml = planSteps.map(s => `<li>${escapeHtml(s.description || s.action || s)}</li>`).join('');

      return `
        <li class="accordion-item" id="issue-${inc.id}">
          <button class="accordion-trigger" aria-expanded="false" aria-controls="issue-${inc.id}-content" data-incident-id="${inc.id}">
            <div class="accordion-left">
              <span class="accordion-num">${num}</span>
              <span class="accordion-heading">${escapeHtml(inc.attack_type || 'Incident')} from ${escapeHtml(inc.src_ip || 'Unknown')}</span>
            </div>
            <div class="back-issue-meta">
              <span class="back-issue-date">${escapeHtml(dateStr)}</span>
              <span class="pill-tag ${probTagClass}">${probPct}%</span>
              <span class="pill-tag pill-tag-olive">${escapeHtml(inc.status || 'recorded')}</span>
            </div>
            <span class="accordion-plus">+</span>
          </button>
          <div id="issue-${inc.id}-content" class="accordion-content">
            <div class="back-issue-content-wrap">
              ${reportText ? `<p class="back-issue-report-text">${escapeHtml(reportText)}</p>` : '<p class="back-issue-report-text" style="font-style:italic; color:var(--ink-muted);">No editorial report recorded for this incident.</p>'}
              ${planStepsHtml ? `<strong class="tiny-label" style="color:var(--forest); display:block; margin-top:0.75rem;">Defensive Containment Sequence</strong><ol class="back-issue-plan-list">${planStepsHtml}</ol>` : ''}
              <div style="margin-top:1rem;">
                <button type="button" class="pill-btn pill-btn-outline-dark view-case-file-btn" style="padding:0.35rem 0.85rem; font-size:0.75rem;" data-id="${inc.id}">
                  Load in Case File →
                </button>
              </div>
            </div>
          </div>
        </li>
      `;
    }).join('');

    initAccordions();

    // Hook 'Load in Case File' buttons
    document.querySelectorAll('.view-case-file-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const incId = parseInt(btn.getAttribute('data-id'), 10);
        const match = incidents.find(i => i.id === incId);
        if (match) {
          loadIncidentIntoCaseFile(match);
        }
      });
    });

  } catch (_) {
    listEl.innerHTML = '<li class="back-issues-placeholder">Unable to retrieve back issues at this time. Our records remain secure.</li>';
  }
}

/**
 * ============================================================================
 * STAGE 2 & 3: Real-Time Telemetry, Chart.js & WebSocket Management
 * ============================================================================
 */

let trafficChart = null;
let wsInstance = null;
let reconnectDelay = 2000;
const MAX_RECONNECT_DELAY = 10000;
let reconnectTimer = null;
let isAttackActive = false;

function initTelemetryWebSocket() {
  const chartCanvas = document.getElementById('traffic-chart');
  if (!chartCanvas) return;

  setupChart(chartCanvas);
  connectWebSocket();
}

function setupChart(canvas) {
  if (typeof Chart === 'undefined') {
    setTimeout(() => setupChart(canvas), 200);
    return;
  }

  const ctx = canvas.getContext('2d');
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  trafficChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Packets / sec',
        data: [],
        borderColor: '#6B705C',
        backgroundColor: 'rgba(107, 112, 92, 0.12)',
        borderWidth: 2,
        tension: prefersReducedMotion ? 0 : 0.35,
        fill: true,
        pointRadius: 0,
        pointHitRadius: 8,
        pointHoverRadius: 4,
        pointHoverBackgroundColor: '#6B705C',
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#1C2A20',
          titleFont: { family: "'DM Sans', -apple-system, sans-serif", size: 11 },
          bodyFont: { family: "'DM Sans', -apple-system, sans-serif", size: 12 },
          padding: 8,
          cornerRadius: 6,
          displayColors: false,
          callbacks: {
            label: (context) => `${context.parsed.y} packets / sec`
          }
        }
      },
      scales: {
        x: {
          grid: { display: false, drawBorder: false },
          ticks: {
            font: { family: "'DM Sans', -apple-system, sans-serif", size: 11 },
            color: '#8A8A7C',
            maxTicksLimit: 7,
            maxRotation: 0,
          }
        },
        y: {
          min: 0,
          suggestedMax: 10,
          grace: '15%',
          grid: { color: 'rgba(38, 38, 31, 0.06)', drawBorder: false },
          ticks: {
            font: { family: "'DM Sans', -apple-system, sans-serif", size: 11 },
            color: '#8A8A7C',
            precision: 0
          }
        }
      }
    }
  });
}

function connectWebSocket() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }

  if (wsInstance) {
    wsInstance.onopen = null;
    wsInstance.onmessage = null;
    wsInstance.onerror = null;
    wsInstance.onclose = null;
    try { wsInstance.close(); } catch (_) {}
    wsInstance = null;
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  try {
    wsInstance = new WebSocket(wsUrl);
  } catch (_) {
    scheduleReconnect();
    return;
  }

  wsInstance.onopen = () => {
    reconnectDelay = 2000;
    updateNetworkStatus(true);
  };

  wsInstance.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      dispatchTelemetryMessage(msg);
    } catch (_) {}
  };

  wsInstance.onclose = (event) => {
    updateNetworkStatus(false);
    if (event.code === 1008) {
      window.location.href = '/login';
      return;
    }
    scheduleReconnect();
  };

  wsInstance.onerror = () => {
    updateNetworkStatus(false);
  };
}

function initReconnectListeners() {
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      if (!wsInstance || wsInstance.readyState === WebSocket.CLOSED || wsInstance.readyState === WebSocket.CLOSING) {
        connectWebSocket();
      }
    }
  });

  window.addEventListener('online', () => {
    if (!wsInstance || wsInstance.readyState === WebSocket.CLOSED || wsInstance.readyState === WebSocket.CLOSING) {
      connectWebSocket();
    }
  });
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectWebSocket();
    reconnectDelay = Math.min(reconnectDelay * 1.5, MAX_RECONNECT_DELAY);
  }, reconnectDelay);
}

/**
 * Route incoming messages by type
 */
function dispatchTelemetryMessage(msg) {
  if (!msg || !msg.type) return;

  switch (msg.type) {
    case 'traffic':
      handleTrafficMessage(msg);
      break;

    case 'attack_started':
      handleAttackStarted(msg);
      break;

    case 'detection':
      handleDetection(msg);
      break;

    case 'route':
      handleRouteMessage(msg);
      break;

    case 'bayes':
      handleBayesMessage(msg);
      break;

    case 'plan':
      handlePlanMessage(msg);
      break;

    case 'report':
      handleReportMessage(msg);
      break;

    case 'resolved':
      handleResolvedMessage(msg);
      break;

    case 'attack_ended':
      handleAttackEnded(msg);
      break;

    case 'watchlist':
      handleWatchlistMessage(msg);
      break;

    case 'reset':
      handleResetMessage(msg);
      break;

    default:
      console.warn('[The Agency] Unhandled telemetry type:', msg.type);
  }
}

function handleTrafficMessage(msg) {
  const ppsEl = document.getElementById('stat-pps');
  const avgSizeEl = document.getElementById('stat-avg-size');
  const blockedEl = document.getElementById('stat-blocked');

  if (ppsEl) ppsEl.textContent = msg.packets;
  if (avgSizeEl) avgSizeEl.textContent = `${Math.round(msg.avg_size)} B`;
  if (blockedEl) blockedEl.textContent = msg.blocked;

  let timeLabel = '';
  if (msg.ts) {
    try {
      const date = new Date(msg.ts);
      timeLabel = date.toTimeString().split(' ')[0];
    } catch (_) {
      timeLabel = msg.ts;
    }
  }

  if (trafficChart) {
    trafficChart.data.labels.push(timeLabel);
    trafficChart.data.datasets[0].data.push(msg.packets);

    while (trafficChart.data.labels.length > 60) {
      trafficChart.data.labels.shift();
      trafficChart.data.datasets[0].data.shift();
    }

    trafficChart.update('none');
  }
}

/**
 * Reset column II (Probability) back to initial calm state
 */
function resetProbabilityColumn() {
  const probBody = document.getElementById('probability-body');
  if (probBody) {
    probBody.innerHTML = `
      <p>Dynamic threat scoring weighs anomalous packet cadence against verified behavioral baselines established over seasonal cycles.</p>
    `;
  }
}

/**
 * Reset column III (The Plan) back to initial calm state
 */
let planCircleTimers = [];
function clearPlanTimers() {
  planCircleTimers.forEach(t => clearTimeout(t));
  planCircleTimers = [];
}

function resetPlanColumn() {
  clearPlanTimers();
  const planBody = document.getElementById('plan-body');
  if (planBody) {
    planBody.innerHTML = `
      <p>Immediate tactical containment isolates adversarial route propagation while network consumers experience uninterrupted serenity.</p>
    `;
  }
}

function handleAttackStarted(msg) {
  isAttackActive = true;
  resetProbabilityColumn();
  resetPlanColumn();

  const attackBtn = document.getElementById('launch-attack-btn');
  if (attackBtn) attackBtn.disabled = true;

  const statusTextEl = document.getElementById('network-status-text');
  const statusDotEl = document.getElementById('network-status-dot');

  if (statusTextEl && statusDotEl) {
    statusTextEl.textContent = 'A disturbance at the gate...';
    statusTextEl.classList.add('status-disconnected');
    statusDotEl.classList.add('disconnected');
  }

  if (trafficChart) {
    trafficChart.data.datasets[0].borderColor = '#B5654A';
    trafficChart.data.datasets[0].backgroundColor = 'rgba(181, 101, 74, 0.15)';
    trafficChart.data.datasets[0].pointHoverBackgroundColor = '#B5654A';
    trafficChart.update('none');
  }

  startCaseDurationTimer();
}

/**
 * ============================================================================
 * STAGE 8: Case File, Geolocation Map, AI Route & Watchlist Management
 * ============================================================================
 */

let caseDurationInterval = null;
let caseStartTime = null;
let currentIncidentAttackers = []; // List of attacker profiles in active incident
let activeSelectedAttackerIp = null;

function startCaseDurationTimer() {
  if (caseDurationInterval) clearInterval(caseDurationInterval);
  caseStartTime = Date.now();
  const durVal = document.getElementById('case-duration');
  const timerPill = document.getElementById('case-file-timer');

  caseDurationInterval = setInterval(() => {
    if (!caseStartTime) return;
    const elapsedSec = ((Date.now() - caseStartTime) / 1000).toFixed(1);
    if (durVal) durVal.textContent = `${elapsedSec}s`;
    if (timerPill) timerPill.textContent = `${elapsedSec}s elapsed`;
  }, 100);
}

function stopCaseDurationTimer() {
  if (caseDurationInterval) {
    clearInterval(caseDurationInterval);
    caseDurationInterval = null;
  }
}

/**
 * Smooth-scroll to Case File and flash border (respecting prefers-reduced-motion)
 */
function scrollAndFlashCaseFile() {
  const caseFileEl = document.getElementById('case-file-section');
  const cardEl = document.getElementById('case-file-card');
  if (!caseFileEl || !cardEl) return;

  const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  caseFileEl.scrollIntoView({
    behavior: prefersReduced ? 'auto' : 'smooth',
    block: 'start'
  });

  cardEl.classList.remove('flash-border');
  void cardEl.offsetWidth; // Force CSS reflow to re-trigger animation
  cardEl.classList.add('flash-border');
}

/**
 * Handle detection event
 */
function handleDetection(msg) {
  // 1. Smooth scroll to Case File & flash border
  scrollAndFlashCaseFile();

  // 2. Cover Story Panel Update
  const coverHeadline = document.getElementById('cover-story-headline');
  const coverBody = document.getElementById('cover-story-body');
  if (coverHeadline) coverHeadline.classList.add('active');

  let formattedTime = 'Just now';
  if (msg.ts) {
    try {
      formattedTime = new Date(msg.ts).toLocaleTimeString();
    } catch (_) {
      formattedTime = msg.ts;
    }
  }

  if (coverBody) {
    coverBody.innerHTML = `
      <div class="cover-incident-details">
        <div class="incident-detail-item">
          <span class="tiny-label">Classification</span>
          <span class="tiny-value">${escapeHtml(msg.attack_type || 'DDoS')}</span>
        </div>
        <div class="incident-detail-item">
          <span class="tiny-label">Ingress Origin</span>
          <span class="tiny-value">${escapeHtml(msg.src_ip || '203.0.113.99')}</span>
        </div>
        <div class="incident-detail-item">
          <span class="tiny-label">Logged At</span>
          <span class="tiny-value">${escapeHtml(formattedTime)}</span>
        </div>
      </div>
    `;
  }

  // 3. Column I: Recognition Card Update with Proof Trace
  const recognitionBody = document.getElementById('recognition-body');
  if (recognitionBody) {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const traceSteps = msg.proof_trace || [];
    const traceItemsHtml = traceSteps.map((step, idx) => {
      const delayMs = prefersReducedMotion ? 0 : idx * 400;
      return `<li class="proof-step" style="animation-delay: ${delayMs}ms;">${escapeHtml(step)}</li>`;
    }).join('');

    recognitionBody.innerHTML = `
      <p class="recognition-callout">I know this one: <em>${escapeHtml(msg.attack_type || 'DDoS')}</em></p>
      <ol class="proof-trace-list">
        ${traceItemsHtml}
      </ol>
    `;
  }

  // 4. Case File Dossier Update
  const caseIdEl = document.getElementById('case-file-id');
  if (caseIdEl) caseIdEl.textContent = `Incident #${msg.incident_id}`;

  const statusChip = document.getElementById('case-file-status-chip');
  if (statusChip) {
    statusChip.className = 'status-chip chip-detected';
    statusChip.textContent = 'Detected';
  }

  const detectedAtEl = document.getElementById('case-detected-at');
  if (detectedAtEl) detectedAtEl.textContent = formattedTime;

  const resolvedAtEl = document.getElementById('case-resolved-at');
  if (resolvedAtEl) resolvedAtEl.textContent = 'Active Investigation';

  const vectorEl = document.getElementById('case-how-vector');
  if (vectorEl) vectorEl.textContent = msg.attack_type || 'DDoS Flood';

  const ruleEl = document.getElementById('case-how-rule');
  if (ruleEl) ruleEl.textContent = msg.rule_fired || 'Horn clause fired';

  // Add attacker profile to session case list
  const attackerProfile = {
    ip: msg.src_ip,
    city: msg.origin_city || 'Geneva',
    country: msg.origin_country || 'Switzerland',
    flag: msg.flag || '🌐',
    lat: msg.lat !== undefined ? msg.lat : 46.2044,
    lon: msg.lon !== undefined ? msg.lon : 6.1432,
    attack_type: msg.attack_type,
    incident_id: msg.incident_id,
  };

  const existingIdx = currentIncidentAttackers.findIndex(a => a.ip === attackerProfile.ip);
  if (existingIdx >= 0) {
    currentIncidentAttackers[existingIdx] = attackerProfile;
  } else {
    currentIncidentAttackers.push(attackerProfile);
  }

  activeSelectedAttackerIp = attackerProfile.ip;
  updateCaseFileAttackerDisplay(attackerProfile);
  renderBotnetTabs();
  renderWorldMap();

  // Timeline step 1 active
  setChronicleStep('step-node-detect', 'active', msg.rule_fired || 'Heuristic logic engine engaged');
}

/**
 * Update the WHERE section for an active attacker profile
 */
function updateCaseFileAttackerDisplay(attacker) {
  const flagEl = document.getElementById('case-where-flag');
  const locEl = document.getElementById('case-where-location');
  const ipEl = document.getElementById('case-where-ip');

  if (flagEl) flagEl.textContent = attacker.flag || '🌐';
  if (locEl) locEl.textContent = `${attacker.city}, ${attacker.country}`;
  if (ipEl) {
    const latStr = attacker.lat !== undefined ? attacker.lat.toFixed(4) : '0.0000';
    const lonStr = attacker.lon !== undefined ? attacker.lon.toFixed(4) : '0.0000';
    ipEl.textContent = `${attacker.ip} • Lat ${latStr}, Lon ${lonStr}`;
  }
}

/**
 * Render Botnet Tabs if there are multiple attackers
 */
function renderBotnetTabs() {
  const tabsStrip = document.getElementById('case-file-tabs-strip');
  if (!tabsStrip) return;

  if (currentIncidentAttackers.length <= 1) {
    tabsStrip.style.display = 'none';
    tabsStrip.innerHTML = '';
    return;
  }

  tabsStrip.style.display = 'flex';
  tabsStrip.innerHTML = '';

  currentIncidentAttackers.forEach(attacker => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `case-tab-btn ${attacker.ip === activeSelectedAttackerIp ? 'active' : ''}`;
    btn.textContent = `${attacker.flag || '🌐'} ${attacker.city} (${attacker.ip})`;
    btn.onclick = () => {
      activeSelectedAttackerIp = attacker.ip;
      updateCaseFileAttackerDisplay(attacker);
      renderBotnetTabs();
      renderWorldMap();
    };
    tabsStrip.appendChild(btn);
  });
}

/**
 * Render dynamic glowing dots and arcs on the SVG World Map
 * Equirectangular formula:
 * x = (lon + 180) * (800 / 360)
 * y = (90 - lat) * (400 / 180)
 * London HQ: lat 51.5074, lon -0.1278 => x = 399.7, y = 85.5
 */
function renderWorldMap() {
  const group = document.getElementById('map-dynamic-attackers');
  if (!group) return;

  group.innerHTML = '';
  const londonX = 399.7;
  const londonY = 85.5;

  currentIncidentAttackers.forEach(attacker => {
    const lat = attacker.lat || 0;
    const lon = attacker.lon || 0;
    const x = (lon + 180) * (800 / 360);
    const y = (90 - lat) * (400 / 180);

    const isSelected = attacker.ip === activeSelectedAttackerIp;

    // Curved SVG arc to London HQ
    const cx = (x + londonX) / 2;
    const cy = Math.min(y, londonY) - (Math.abs(x - londonX) * 0.15 + 25);
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', `M ${x.toFixed(1)} ${y.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${londonX} ${londonY}`);
    path.setAttribute('class', 'attack-arc-path');
    if (!isSelected && currentIncidentAttackers.length > 1) {
      path.setAttribute('opacity', '0.45');
    }
    group.appendChild(path);

    // Pulsing outer ring
    const ring = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    ring.setAttribute('cx', x.toFixed(1));
    ring.setAttribute('cy', y.toFixed(1));
    ring.setAttribute('r', isSelected ? '14' : '10');
    ring.setAttribute('class', 'attacker-ring pulse');
    group.appendChild(ring);

    // Solid core dot
    const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    dot.setAttribute('cx', x.toFixed(1));
    dot.setAttribute('cy', y.toFixed(1));
    dot.setAttribute('r', isSelected ? '6' : '4.5');
    dot.setAttribute('class', 'attacker-dot');
    group.appendChild(dot);

    // City label
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', (x + 8).toFixed(1));
    text.setAttribute('y', (y + 3).toFixed(1));
    text.setAttribute('class', 'attacker-map-label');
    text.textContent = `${attacker.city} ${attacker.flag || ''}`;
    group.appendChild(text);
  });
}

/**
 * Handle AI Search & Route Tracing event
 */
function handleRouteMessage(msg) {
  // 1. Update comparison pill
  const pill = document.getElementById('ai-search-comparison-pill');
  if (pill && msg.comparison_text) {
    pill.textContent = msg.comparison_text;
    pill.className = 'pill-tag pill-tag-terracotta';
  }

  // 2. Update search stats
  const bfsVal = document.getElementById('bfs-explored-val');
  if (bfsVal && msg.bfs) {
    bfsVal.textContent = `BFS explored ${msg.bfs.explored_count} nodes`;
  }

  const astarVal = document.getElementById('astar-explored-val');
  if (astarVal && msg.astar) {
    astarVal.textContent = `A* explored ${msg.astar.explored_count} nodes (optimal, cost: ${msg.astar.cost})`;
  }

  const pathVal = document.getElementById('ai-path-val');
  if (pathVal && msg.astar && msg.astar.path) {
    pathVal.textContent = msg.astar.path.join(' → ');
  }

  // 3. Animate Network Topology SVG
  animateTopologyPath(msg.astar ? msg.astar.path : []);
}

function animateTopologyPath(pathNodes) {
  // Clear previous active nodes & edges
  document.querySelectorAll('.topo-node .node-circle').forEach(c => c.classList.remove('node-active'));
  document.querySelectorAll('.topology-edges .edge-line').forEach(e => e.classList.remove('edge-active'));

  const attackerCircle = document.querySelector('#topo-node-attacker .node-circle');
  if (attackerCircle) attackerCircle.classList.add('node-active');

  const edgeAttacker = document.getElementById('edge-attacker-gateway');
  if (edgeAttacker) edgeAttacker.classList.add('edge-active');

  const nodeMap = {
    'Gateway Router': 'topo-node-gateway',
    'External Firewall': 'topo-node-firewall',
    'Core Switch': 'topo-node-core',
    'Web Server': 'topo-node-web',
    'SSH Bastion': 'topo-node-ssh',
    'Database Server': 'topo-node-db',
  };

  const edgeMap = {
    'Gateway Router->External Firewall': 'edge-gateway-firewall',
    'External Firewall->Core Switch': 'edge-firewall-core',
    'Core Switch->Web Server': 'edge-core-web',
    'Core Switch->SSH Bastion': 'edge-core-ssh',
    'Core Switch->Database Server': 'edge-core-db',
  };

  pathNodes.forEach(nodeName => {
    const id = nodeMap[nodeName];
    if (id) {
      const circle = document.querySelector(`#${id} .node-circle`);
      if (circle) circle.classList.add('node-active');
    }
  });

  for (let i = 0; i < pathNodes.length - 1; i++) {
    const key = `${pathNodes[i]}->${pathNodes[i + 1]}`;
    const edgeId = edgeMap[key];
    if (edgeId) {
      const edge = document.getElementById(edgeId);
      if (edge) edge.classList.add('edge-active');
    }
  }
}

/**
 * Handle bayes event (Module 5)
 */
function handleBayesMessage(msg) {
  const probBody = document.getElementById('probability-body');
  if (!probBody) return;

  const prior = msg.prior !== undefined ? msg.prior : 0.05;
  const posterior = msg.posterior !== undefined ? msg.posterior : 0.95;
  const priorPct = Math.round(prior * 100);
  const postPct = Math.round(posterior * 100);
  const isMalicious = postPct >= 80;
  const steps = msg.steps || [];

  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const allSteps = [
    `Starting belief: ${priorPct}%`,
    ...steps.map(s => `${escapeHtml(s.label)} &rarr; ${Math.round(s.posterior * 100)}%`)
  ];

  const stepsHtml = allSteps.map((stepText, idx) => {
    const delayMs = prefersReducedMotion ? 0 : idx * 500;
    return `<li class="bayes-step" style="animation-delay: ${delayMs}ms;">${stepText}</li>`;
  }).join('');

  const initialOffset = 301.6 * (1 - (priorPct / 100));

  probBody.innerHTML = `
    <div class="bayes-gauge-container">
      <svg class="bayes-radial-gauge" viewBox="0 0 120 120" style="transform: rotate(-90deg);" aria-hidden="true">
        <circle class="gauge-track" cx="60" cy="60" r="48" fill="none" stroke-width="8"></circle>
        <circle class="gauge-indicator" id="gauge-circle" cx="60" cy="60" r="48" fill="none" stroke-width="8"
          stroke-dasharray="301.6" stroke-dashoffset="${initialOffset}" stroke-linecap="round"></circle>
      </svg>
      <div class="gauge-center-text">
        <span id="gauge-percent-display">${priorPct}%</span>
      </div>
    </div>
    <p class="bayes-verdict ${isMalicious ? 'malicious' : 'benign'}">
      <em>${isMalicious ? 'Probably malicious' : 'Probably benign'}</em>
    </p>
    <ol class="bayes-steps-list">
      ${stepsHtml}
    </ol>
  `;

  // Animate gauge arc from prior to posterior
  setTimeout(() => {
    const circle = document.getElementById('gauge-circle');
    const label = document.getElementById('gauge-percent-display');
    if (!circle || !label) return;

    const targetOffset = 301.6 * (1 - (postPct / 100));
    circle.style.transition = prefersReducedMotion ? 'none' : 'stroke-dashoffset 1.5s cubic-bezier(0.4, 0, 0.2, 1)';
    circle.style.strokeDashoffset = targetOffset;
    circle.style.stroke = isMalicious ? '#B5654A' : '#6B705C';

    if (prefersReducedMotion) {
      label.textContent = `${postPct}%`;
    } else {
      let currentVal = priorPct;
      const stepTime = 1500 / Math.max(1, Math.abs(postPct - priorPct));
      const counterTimer = setInterval(() => {
        if (currentVal < postPct) {
          currentVal++;
          label.textContent = `${currentVal}%`;
        } else if (currentVal > postPct) {
          currentVal--;
          label.textContent = `${currentVal}%`;
        } else {
          clearInterval(counterTimer);
        }
      }, stepTime);
    }
  }, 100);

  // Update Case File status and timeline
  const statusChip = document.getElementById('case-file-status-chip');
  if (statusChip) {
    statusChip.className = 'status-chip chip-analyzing';
    statusChip.textContent = 'Analyzing';
  }

  setChronicleStep('step-node-detect', 'completed');
  setChronicleStep('step-node-bayes', 'active', `Bayesian posterior assessed: ${postPct}%`);
}

/**
 * Handle plan event (Module 6)
 */
function handlePlanMessage(msg) {
  clearPlanTimers();
  const planBody = document.getElementById('plan-body');
  if (!planBody) return;

  const steps = msg.steps || [];
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const rowsHtml = steps.map((step, idx) => {
    const delayMs = prefersReducedMotion ? 0 : idx * 400;
    return `
      <li class="plan-step-row" style="animation-delay: ${delayMs}ms;">
        <span class="plan-step-indicator" id="plan-indicator-${idx}">${step.n}</span>
        <div class="plan-step-details">
          <span class="plan-step-text">${escapeHtml(step.description)}</span>
        </div>
      </li>
    `;
  }).join('');

  const statesExploredText = msg.states_explored !== undefined
    ? `<span class="plan-states-count">Explored ${msg.states_explored} states in STRIPS search</span>`
    : '';

  planBody.innerHTML = `
    <ol class="plan-steps-list">
      ${rowsHtml}
    </ol>
    <div class="plan-footer-wrap">
      ${statesExploredText}
    </div>
  `;

  if (!prefersReducedMotion && steps.length > 0) {
    const allRowsAppearedTime = steps.length * 400 + 200;
    steps.forEach((_, idx) => {
      const timer = setTimeout(() => {
        const ind = document.getElementById(`plan-indicator-${idx}`);
        if (ind) ind.classList.add('completed');
      }, allRowsAppearedTime + (idx * 500));
      planCircleTimers.push(timer);
    });
  }

  // Update Case File status and timeline
  const statusChip = document.getElementById('case-file-status-chip');
  if (statusChip) {
    statusChip.className = 'status-chip chip-analyzing';
    statusChip.textContent = 'Defense Planned';
  }

  setChronicleStep('step-node-bayes', 'completed');
  setChronicleStep('step-node-plan', 'active', `STRIPS containment sequence synthesized (${steps.length} steps)`);
}

/**
 * Handle report event (Module 6 / Stage 6)
 */
function handleReportMessage(msg) {
  const headlineEl = document.getElementById('incident-report-headline');
  if (headlineEl) headlineEl.innerHTML = 'The Gate Was <em>Secured</em>';

  const modelTagEl = document.getElementById('incident-report-model-tag');
  if (modelTagEl) {
    const isGemini = (msg.generated_by || '').toLowerCase() === 'gemini';
    modelTagEl.textContent = isGemini ? 'Gemini' : 'Template';
    modelTagEl.className = `pill-tag ${isGemini ? 'pill-tag-olive' : 'pill-tag-terracotta'}`;
    modelTagEl.style.display = 'inline-block';
  }

  const timestampEl = document.getElementById('incident-report-timestamp');
  if (timestampEl && msg.ts) {
    try {
      const d = new Date(msg.ts);
      timestampEl.textContent = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (_) {
      timestampEl.textContent = msg.ts;
    }
  }

  const bodyEl = document.getElementById('incident-report-body');
  if (bodyEl && msg.body) {
    bodyEl.innerHTML = '';
    const paragraphs = msg.body.split(/\n\s*\n/).filter(p => p.trim().length > 0);
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    paragraphs.forEach((pText, idx) => {
      const p = document.createElement('p');
      p.className = 'editorial-paragraph';
      p.style.animationDelay = prefersReducedMotion ? '0ms' : `${idx * 400}ms`;

      if (idx === 0 && pText.length > 0) {
        const dropCap = document.createElement('span');
        dropCap.className = 'drop-cap';
        dropCap.textContent = pText[0];
        p.appendChild(dropCap);
        p.appendChild(document.createTextNode(pText.substring(1)));
      } else {
        p.textContent = pText;
      }
      bodyEl.appendChild(p);
    });
  }

  const pullquoteEl = document.getElementById('incident-report-pullquote');
  const pullquoteWrap = document.getElementById('incident-report-pullquote-wrap');
  if (pullquoteEl && msg.body) {
    const firstSentence = msg.body.split(/[.!?]/)[0].trim();
    if (firstSentence) pullquoteEl.textContent = `“${firstSentence}.”`;
    if (pullquoteWrap) pullquoteWrap.classList.add('editorial-hairlines');
  }

  // Update Case File timeline
  setChronicleStep('step-node-plan', 'completed');
  setChronicleStep('step-node-report', 'active', `Concierge dispatch compiled via ${msg.generated_by || 'editorial concierge'}`);
}

/**
 * Handle resolved event
 */
function handleResolvedMessage(msg) {
  isAttackActive = false;
  stopCaseDurationTimer();

  const attackBtn = document.getElementById('launch-attack-btn');
  if (attackBtn) attackBtn.disabled = false;

  const statusTextEl = document.getElementById('network-status-text');
  const statusDotEl = document.getElementById('network-status-dot');
  if (statusTextEl && statusDotEl) {
    statusTextEl.textContent = 'Threat blocked. All quiet on the network.';
    statusTextEl.classList.remove('status-disconnected');
    statusDotEl.classList.remove('disconnected');
  }

  if (trafficChart) {
    trafficChart.data.datasets[0].borderColor = '#6B705C';
    trafficChart.data.datasets[0].backgroundColor = 'rgba(107, 112, 92, 0.12)';
    trafficChart.data.datasets[0].pointHoverBackgroundColor = '#6B705C';
    trafficChart.update('none');
  }

  const resolvedTag = document.getElementById('cover-story-resolved-tag');
  if (resolvedTag) resolvedTag.style.display = 'inline-block';

  document.querySelectorAll('.plan-step-indicator').forEach(el => el.classList.add('completed'));

  // Update Case File
  const statusChip = document.getElementById('case-file-status-chip');
  if (statusChip) {
    statusChip.className = 'status-chip chip-resolved';
    statusChip.textContent = 'Resolved';
  }

  const resolvedAtEl = document.getElementById('case-resolved-at');
  if (resolvedAtEl) {
    const now = new Date();
    resolvedAtEl.textContent = now.toLocaleTimeString();
  }

  setChronicleStep('step-node-report', 'completed');
  setChronicleStep('step-node-resolve', 'completed', 'Threat blocked • Sanctuary restored');

  loadBackIssues();
  loadWatchlist();
}

function handleAttackEnded(msg) {
  isAttackActive = false;
  stopCaseDurationTimer();

  const attackBtn = document.getElementById('launch-attack-btn');
  if (attackBtn) attackBtn.disabled = false;

  const statusTextEl = document.getElementById('network-status-text');
  const statusDotEl = document.getElementById('network-status-dot');
  if (statusTextEl && statusDotEl) {
    statusTextEl.textContent = 'All quiet on the network.';
    statusTextEl.classList.remove('status-disconnected');
    statusDotEl.classList.remove('disconnected');
  }

  if (trafficChart) {
    trafficChart.data.datasets[0].borderColor = '#6B705C';
    trafficChart.data.datasets[0].backgroundColor = 'rgba(107, 112, 92, 0.12)';
    trafficChart.data.datasets[0].pointHoverBackgroundColor = '#6B705C';
    trafficChart.update('none');
  }
}

function updateNetworkStatus(isConnected) {
  if (isAttackActive) return;

  const statusTextEl = document.getElementById('network-status-text');
  const statusDotEl = document.getElementById('network-status-dot');
  if (!statusTextEl || !statusDotEl) return;

  if (isConnected) {
    statusTextEl.textContent = 'All quiet on the network.';
    statusTextEl.classList.remove('status-disconnected');
    statusDotEl.classList.remove('disconnected');
  } else {
    statusTextEl.textContent = 'Reconnecting to the network...';
    statusTextEl.classList.add('status-disconnected');
    statusDotEl.classList.add('disconnected');
  }
}

/**
 * Update vertical chronicle step visual states
 */
function setChronicleStep(stepId, state, descText) {
  const step = document.getElementById(stepId);
  if (!step) return;

  step.classList.remove('step-pending', 'step-active', 'step-completed');
  if (state === 'active') {
    step.classList.add('step-active');
  } else if (state === 'completed') {
    step.classList.add('step-completed');
  } else {
    step.classList.add('step-pending');
  }

  if (descText) {
    const desc = step.querySelector('.step-desc');
    if (desc) desc.textContent = descText;
  }
}

function resetChronicleSteps() {
  ['step-node-detect', 'step-node-bayes', 'step-node-plan', 'step-node-report', 'step-node-resolve'].forEach(id => {
    setChronicleStep(id, 'pending');
  });
}

/**
 * Watchlist rendering & fetching
 */
async function loadWatchlist() {
  try {
    const res = await fetch('/api/watchlist', {
      headers: { 'Accept': 'application/json' }
    });
    if (res.ok) {
      const list = await res.json();
      renderWatchlistTable(list);
    }
  } catch (_) {}
}

function handleWatchlistMessage(msg) {
  if (msg && Array.isArray(msg.watchlist)) {
    renderWatchlistTable(msg.watchlist);
  }
}

function renderWatchlistTable(rows) {
  const tbody = document.getElementById('watchlist-table-body');
  const badge = document.getElementById('watchlist-count-badge');
  if (!tbody) return;

  if (badge) {
    badge.textContent = `${rows.length} Monitored ${rows.length === 1 ? 'Entry' : 'Entries'}`;
  }

  if (!rows || rows.length === 0) {
    tbody.innerHTML = `
      <tr class="watchlist-empty-row">
        <td colspan="6" class="empty-state-cell">No intrusion signatures logged in current surveillance cycle.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = '';
  rows.forEach(item => {
    const tr = document.createElement('tr');
    tr.setAttribute('data-ip', item.ip);

    // IP cell
    const tdIp = document.createElement('td');
    const spanIp = document.createElement('span');
    spanIp.className = 'ip-mono';
    spanIp.textContent = item.ip;
    tdIp.appendChild(spanIp);
    tr.appendChild(tdIp);

    // Origin cell
    const tdOrigin = document.createElement('td');
    tdOrigin.textContent = `${item.flag || '🌐'} ${item.city}, ${item.country}`;
    tr.appendChild(tdOrigin);

    // Vector cell
    const tdVector = document.createElement('td');
    tdVector.textContent = item.attack_type || 'DDoS';
    tr.appendChild(tdVector);

    // Prob cell
    const tdProb = document.createElement('td');
    const probPct = Math.round((item.probability !== undefined ? item.probability : 0.05) * 100);
    const spanProb = document.createElement('span');
    spanProb.className = `pill-tag ${probPct >= 80 ? 'pill-tag-terracotta' : 'pill-tag-olive'}`;
    spanProb.textContent = `${probPct}%`;
    tdProb.appendChild(spanProb);
    tr.appendChild(tdProb);

    // Packets cell
    const tdPkts = document.createElement('td');
    tdPkts.textContent = String(item.packets || 0);
    tr.appendChild(tdPkts);

    // Status cell
    const tdStatus = document.createElement('td');
    const spanStatus = document.createElement('span');
    const statusLower = (item.status || 'monitored').toLowerCase();
    let chipClass = 'chip-detected';
    if (statusLower.includes('block') || statusLower.includes('neutral')) chipClass = 'chip-resolved';
    else if (statusLower.includes('analyz')) chipClass = 'chip-analyzing';
    spanStatus.className = `status-chip ${chipClass}`;
    spanStatus.textContent = item.status || 'Monitored';
    tdStatus.appendChild(spanStatus);
    tr.appendChild(tdStatus);

    // Click on watchlist row highlights attacker on map and scrolls to Case File
    tr.addEventListener('click', () => {
      document.querySelectorAll('#watchlist-table-body tr').forEach(r => r.classList.remove('row-selected'));
      tr.classList.add('row-selected');
      activeSelectedAttackerIp = item.ip;
      updateCaseFileAttackerDisplay(item);
      renderWorldMap();
      scrollAndFlashCaseFile();
    });

    tbody.appendChild(tr);
  });
}

/**
 * Load back issue into active Case File
 */
function loadIncidentIntoCaseFile(inc) {
  const caseIdEl = document.getElementById('case-file-id');
  if (caseIdEl) caseIdEl.textContent = `Incident #${inc.id}`;

  const statusChip = document.getElementById('case-file-status-chip');
  if (statusChip) {
    statusChip.className = 'status-chip chip-resolved';
    statusChip.textContent = inc.status || 'Resolved';
  }

  let formattedTime = 'Past cycle';
  if (inc.ts) {
    try { formattedTime = new Date(inc.ts).toLocaleTimeString(); } catch (_) {}
  }
  const detectedAtEl = document.getElementById('case-detected-at');
  if (detectedAtEl) detectedAtEl.textContent = formattedTime;

  const resolvedAtEl = document.getElementById('case-resolved-at');
  if (resolvedAtEl) resolvedAtEl.textContent = inc.blocked_at ? new Date(inc.blocked_at).toLocaleTimeString() : 'Resolved';

  const vectorEl = document.getElementById('case-how-vector');
  if (vectorEl) vectorEl.textContent = inc.attack_type || 'DDoS';

  const attacker = {
    ip: inc.src_ip,
    city: inc.origin_city || 'Geneva',
    country: inc.origin_country || 'Switzerland',
    flag: '🌐',
    lat: 46.2044,
    lon: 6.1432,
    attack_type: inc.attack_type,
    incident_id: inc.id,
  };

  currentIncidentAttackers = [attacker];
  activeSelectedAttackerIp = attacker.ip;
  updateCaseFileAttackerDisplay(attacker);
  renderBotnetTabs();
  renderWorldMap();

  if (inc.route) {
    handleRouteMessage(inc.route);
  }

  scrollAndFlashCaseFile();
}

/**
 * Handle reset event
 */
function handleResetMessage(msg) {
  isAttackActive = false;
  stopCaseDurationTimer();
  currentIncidentAttackers = [];
  activeSelectedAttackerIp = null;

  const attackBtn = document.getElementById('launch-attack-btn');
  if (attackBtn) attackBtn.disabled = false;

  const statusTextEl = document.getElementById('network-status-text');
  const statusDotEl = document.getElementById('network-status-dot');
  if (statusTextEl && statusDotEl) {
    statusTextEl.textContent = 'All quiet on the network.';
    statusTextEl.classList.remove('status-disconnected');
    statusDotEl.classList.remove('disconnected');
  }

  if (trafficChart) {
    trafficChart.data.datasets[0].borderColor = '#6B705C';
    trafficChart.data.datasets[0].backgroundColor = 'rgba(107, 112, 92, 0.12)';
    trafficChart.data.datasets[0].pointHoverBackgroundColor = '#6B705C';
    trafficChart.update('none');
  }

  // Reset Cover Story
  const coverHeadline = document.getElementById('cover-story-headline');
  if (coverHeadline) coverHeadline.classList.remove('active');
  const resolvedTag = document.getElementById('cover-story-resolved-tag');
  if (resolvedTag) resolvedTag.style.display = 'none';
  const coverBody = document.getElementById('cover-story-body');
  if (coverBody) {
    coverBody.innerHTML = `
      <p class="placeholder-copy">
        A gentle anomaly emerged along the northern perimeter relay at twilight. Correlated via heuristic analysis, quarantined before the estate bells tolled. Full incident log reserved for active dispatch.
      </p>
    `;
  }

  // Reset Recognition, Probability & Plan
  const recognitionBody = document.getElementById('recognition-body');
  if (recognitionBody) {
    recognitionBody.innerHTML = `
      <p>Signature classification distinguishes mundane automated probes from tailored intrusions targeting private infrastructure.</p>
    `;
  }
  resetProbabilityColumn();
  resetPlanColumn();

  // Reset Case File
  const caseIdEl = document.getElementById('case-file-id');
  if (caseIdEl) caseIdEl.textContent = 'Incident #--';

  const statusChip = document.getElementById('case-file-status-chip');
  if (statusChip) {
    statusChip.className = 'status-chip chip-detected';
    statusChip.textContent = 'Awaiting Intrusion';
  }

  const timerPill = document.getElementById('case-file-timer');
  if (timerPill) timerPill.textContent = '0.0s elapsed';

  const detectedAtEl = document.getElementById('case-detected-at');
  if (detectedAtEl) detectedAtEl.textContent = '—';

  const durVal = document.getElementById('case-duration');
  if (durVal) durVal.textContent = '0.0s';

  const resolvedAtEl = document.getElementById('case-resolved-at');
  if (resolvedAtEl) resolvedAtEl.textContent = 'Pending';

  const flagEl = document.getElementById('case-where-flag');
  if (flagEl) flagEl.textContent = '🌐';

  const locEl = document.getElementById('case-where-location');
  if (locEl) locEl.textContent = 'Awaiting coordinate fix';

  const ipEl = document.getElementById('case-where-ip');
  if (ipEl) ipEl.textContent = '0.0.0.0 • Lat 0.0000, Lon 0.0000';

  const vectorEl = document.getElementById('case-how-vector');
  if (vectorEl) vectorEl.textContent = 'DDoS Flood';

  const ruleEl = document.getElementById('case-how-rule');
  if (ruleEl) ruleEl.textContent = 'Awaiting Horn clause';

  const mapGroup = document.getElementById('map-dynamic-attackers');
  if (mapGroup) mapGroup.innerHTML = '';

  const tabsStrip = document.getElementById('case-file-tabs-strip');
  if (tabsStrip) {
    tabsStrip.style.display = 'none';
    tabsStrip.innerHTML = '';
  }

  resetChronicleSteps();

  // Reset Topology Map
  document.querySelectorAll('.topo-node .node-circle').forEach(c => c.classList.remove('node-active'));
  document.querySelectorAll('.topology-edges .edge-line').forEach(e => e.classList.remove('edge-active'));
  const pill = document.getElementById('ai-search-comparison-pill');
  if (pill) {
    pill.textContent = 'AI Search: Standby';
    pill.className = 'pill-tag pill-tag-forest';
  }
  const bfsVal = document.getElementById('bfs-explored-val');
  if (bfsVal) bfsVal.textContent = 'Standby (0 nodes)';
  const astarVal = document.getElementById('astar-explored-val');
  if (astarVal) astarVal.textContent = 'Standby (0 nodes)';
  const pathVal = document.getElementById('ai-path-val');
  if (pathVal) pathVal.textContent = '—';

  // Reset Incident Report
  const reportHeadline = document.getElementById('incident-report-headline');
  if (reportHeadline) reportHeadline.innerHTML = 'Incident Report';
  const modelTag = document.getElementById('incident-report-model-tag');
  if (modelTag) modelTag.style.display = 'none';
  const reportTs = document.getElementById('incident-report-timestamp');
  if (reportTs) reportTs.textContent = '';
  const reportBody = document.getElementById('incident-report-body');
  if (reportBody) {
    reportBody.innerHTML = `
      <p>
        <span class="drop-cap">A</span>t three minutes past midnight, beneath an overcast autumn sky, the gateway telemetry recorded an unannounced sequence of syn-flood packets originating from a distributed residential cluster. The intrusion was calculated to mimic casual browsing, yet the cadence betrayed synthetic coordination.
      </p>
      <p>
        Within eleven milliseconds, the heuristic engine engaged silent diversion protocols. Rather than escalating audible alerts or disrupting ongoing media streams within the main villa, the ingress route was gently shifted to an ephemeral virtual sandbox. The attacker perceived success; the estate remained tranquil.
      </p>
    `;
  }
  const pullquote = document.getElementById('incident-report-pullquote');
  if (pullquote) {
    pullquote.textContent = '“In the silence of the estate, true defense is invisible, anticipating the whisper before the storm.”';
  }
  const pullquoteWrap = document.getElementById('incident-report-pullquote-wrap');
  if (pullquoteWrap) pullquoteWrap.classList.remove('editorial-hairlines');

  loadBackIssues();
  renderWatchlistTable([]);
}
