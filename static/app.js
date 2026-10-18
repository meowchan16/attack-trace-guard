/**
 * The Agency — Boutique Cybersecurity Agency Dashboard
 * Client-side script:
 * - Date formatting & agent profile loading
 * - Accordion interactions
 * - WebSocket client with auto-reconnect (2s backing off to 10s)
 * - Real-time Chart.js line chart with dynamic color shifting (olive -> terracotta on attack)
 * - Attack simulation trigger (/api/attack)
 * - Live incident detection, Cover Story activation & Recognition proof trace streaming
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

  // Update login top strip date if present
  const loginDateEl = document.getElementById('today-date-login');
  if (loginDateEl) {
    loginDateEl.textContent = formattedShort;
  }

  // Update dashboard hero date if present
  const dashboardHeroDateEl = document.getElementById('today-date-dashboard');
  if (dashboardHeroDateEl) {
    dashboardHeroDateEl.textContent = formattedLong;
  }
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
      headers: {
        'Accept': 'application/json'
      }
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
    btn.addEventListener('click', () => {
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
    });
  });
}

/**
 * ============================================================================
 * STAGE 3: Attack Trigger Handler (/api/attack)
 * ============================================================================
 */

function initAttackButton() {
  const attackBtn = document.getElementById('launch-attack-btn');
  if (!attackBtn) return;

  attackBtn.addEventListener('click', async () => {
    if (attackBtn.disabled) return;
    attackBtn.disabled = true;

    try {
      const res = await fetch('/api/attack', {
        method: 'POST',
        headers: {
          'Accept': 'application/json'
        }
      });

      if (res.status === 409) {
        // Attack already in progress; keep button disabled
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
        headers: {
          'Accept': 'application/json'
        }
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
          <button class="accordion-trigger" aria-expanded="false" aria-controls="issue-${inc.id}-content">
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
            </div>
          </div>
        </li>
      `;
    }).join('');

    initAccordions();
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

/**
 * Initialize Chart.js with nature-retreat styling:
 * - Olive (#6B705C) smooth line by default, shifts to terracotta (#B5654A) during attack
 * - Faint hairlines, DM Sans typography, no legend clutter
 * - Zero animation delay for seamless 1-second live scrolling
 * - Last 60 seconds rolling window
 */
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
        legend: {
          display: false
        },
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
          grid: {
            display: false,
            drawBorder: false
          },
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
          grid: {
            color: 'rgba(38, 38, 31, 0.06)',
            drawBorder: false
          },
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

/**
 * Establish resilient WebSocket connection
 */
function connectWebSocket() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }

  // Cleanly teardown any prior socket to prevent duplicate connections or listeners
  if (wsInstance) {
    wsInstance.onopen = null;
    wsInstance.onmessage = null;
    wsInstance.onerror = null;
    wsInstance.onclose = null;
    try {
      wsInstance.close();
    } catch (_) {}
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

/**
 * Handle tab wake-up and network restoration without duplicate sockets
 */
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

/**
 * Exponential backoff schedule
 */
function scheduleReconnect() {
  if (reconnectTimer) return;

  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectWebSocket();
    reconnectDelay = Math.min(reconnectDelay * 1.5, MAX_RECONNECT_DELAY);
  }, reconnectDelay);
}

/**
 * Route incoming messages by type (extensible for Stages 3, 4, 5)
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

    case 'attack_ended':
      handleAttackEnded(msg);
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
    case 'reset':
      handleResetMessage(msg);
      break;

    default:
      console.warn('[The Agency] Unhandled telemetry type:', msg.type);
  }
}

/**
 * Update real-time metrics and Chart.js streaming curve
 */
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
function resetPlanColumn() {
  clearPlanTimers();
  const planBody = document.getElementById('plan-body');
  if (planBody) {
    planBody.innerHTML = `
      <p>Immediate tactical containment isolates adversarial route propagation while network consumers experience uninterrupted serenity.</p>
    `;
  }
}

/**
 * Handle attack_started event:
 * - Update status line to "A disturbance at the gate..." in terracotta
 * - Shift chart line color to terracotta
 * - Disable Launch Attack button
 * - Reset Probability and Plan columns for upcoming analysis
 */
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

  // Shift Chart to terracotta
  if (trafficChart) {
    trafficChart.data.datasets[0].borderColor = '#B5654A';
    trafficChart.data.datasets[0].backgroundColor = 'rgba(181, 101, 74, 0.15)';
    trafficChart.data.datasets[0].pointHoverBackgroundColor = '#B5654A';
    trafficChart.update('none');
  }
}

/**
 * Handle detection event:
 * - Cover Story panel comes alive (headline bright, card with attack type, IP, time)
 * - "I. Recognition" column displays: "I know this one: *DDoS*" with 400ms staggered proof trace
 */
function handleDetection(msg) {
  // 1. Cover Story Panel Update
  const coverHeadline = document.getElementById('cover-story-headline');
  const coverBody = document.getElementById('cover-story-body');

  if (coverHeadline) {
    coverHeadline.classList.add('active');
  }

  if (coverBody) {
    let formattedTime = 'Just now';
    if (msg.ts) {
      try {
        formattedTime = new Date(msg.ts).toLocaleTimeString();
      } catch (_) {
        formattedTime = msg.ts;
      }
    }

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

  // 2. Column I: Recognition Card Update with Proof Trace
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
}

/**
 * Handle bayes event (Module 5):
 * - Renders radial SVG gauge with centered percentage
 * - Shows italic verdict: "Probably malicious" (>= 80%) or "Probably benign" (< 80%)
 * - Four step reasoning lines staggered by 500ms
 * - Animates gauge from prior (5%) to posterior (~95%) over 1.5s
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

  // 120x120 SVG, radius 48 => circumference ~ 301.6
  // Prior 5% => initial offset 286.5
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
      Probably <em>${isMalicious ? 'malicious' : 'benign'}</em>
    </p>
    <ul class="bayes-step-list">
      ${stepsHtml}
    </ul>
    <div class="bayes-prior-footnote">Naive Bayes, prior ${priorPct}%</div>
  `;

  animateGauge(priorPct, postPct, isMalicious);
}

/**
 * Animate the radial gauge sweep from prior to posterior over 1.5 seconds
 */
function animateGauge(startPct, endPct, isTerracotta) {
  const circle = document.getElementById('gauge-circle');
  const percentText = document.getElementById('gauge-percent-display');
  if (!circle || !percentText) return;

  if (isTerracotta) {
    circle.classList.add('terracotta');
  } else {
    circle.classList.remove('terracotta');
  }

  const circumference = 301.6;
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  if (prefersReducedMotion) {
    const finalOffset = circumference * (1 - (endPct / 100));
    circle.style.strokeDashoffset = finalOffset;
    percentText.textContent = `${Math.round(endPct)}%`;
    return;
  }

  const durationMs = 1500;
  let startTime = null;

  function step(timestamp) {
    if (!startTime) startTime = timestamp;
    const elapsed = timestamp - startTime;
    const progress = Math.min(elapsed / durationMs, 1.0);

    // Ease-out cubic: 1 - Math.pow(1 - progress, 3)
    const eased = 1 - Math.pow(1 - progress, 3);
    const currentPct = startPct + (endPct - startPct) * eased;
    const currentOffset = circumference * (1 - (currentPct / 100));

    circle.style.strokeDashoffset = currentOffset;
    percentText.textContent = `${Math.round(currentPct)}%`;

    if (progress < 1.0) {
      requestAnimationFrame(step);
    } else {
      circle.style.strokeDashoffset = circumference * (1 - (endPct / 100));
      percentText.textContent = `${Math.round(endPct)}%`;
    }
  }

  requestAnimationFrame(step);
}

/**
 * Convert small integer to title-cased English word
 */
function numberToWord(n) {
  const words = ['Zero', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine', 'Ten'];
  return words[n] || String(n);
}

let planCircleTimers = [];

function clearPlanTimers() {
  planCircleTimers.forEach(t => clearTimeout(t));
  planCircleTimers = [];
}

/**
 * Handle plan event (Module 6):
 * - Displays headline with step count: "Three steps to <em>safety</em>"
 * - Editorial numbered rows fading in 600ms after the previous one
 * - After all steps have appeared, circles fill in olive one by one (every 500ms) with checkmark
 * - Footnote showing states explored
 * - Respects prefers-reduced-motion (shows all immediately)
 */
function handlePlanMessage(msg) {
  clearPlanTimers();

  const planBody = document.getElementById('plan-body');
  if (!planBody) return;

  const steps = msg.steps || [];
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const stepWord = numberToWord(steps.length);
  const headlineSuffix = steps.length === 1 ? 'step to <em>safety</em>' : 'steps to <em>safety</em>';
  const headlineHtml = `<p class="plan-headline">${stepWord} ${headlineSuffix}</p>`;

  const rowsHtml = steps.map((step, idx) => {
    const delayMs = prefersReducedMotion ? 0 : idx * 600;
    const stepNum = step.n !== undefined ? step.n : idx + 1;
    return `
      <li class="plan-step-row" style="animation-delay: ${delayMs}ms;" data-step-index="${idx}">
        <span class="plan-step-num">${stepNum}</span>
        <div class="plan-step-content">
          <p class="plan-step-desc">${escapeHtml(step.description)}</p>
        </div>
        <div class="plan-step-indicator ${prefersReducedMotion ? 'completed' : ''}" id="plan-indicator-${idx}" aria-label="Step completed">
          <svg class="plan-check-icon" viewBox="0 0 16 16" fill="none">
            <path d="M3.5 8.5L6.5 11.5L12.5 4.5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
      </li>
    `;
  }).join('');

  const statesExplored = msg.states_explored !== undefined ? msg.states_explored : 5;
  const footnoteHtml = `<div class="plan-footnote">Planned by search over ${statesExplored} possible states.</div>`;

  planBody.innerHTML = `
    ${headlineHtml}
    <ul class="plan-step-list">
      ${rowsHtml}
    </ul>
    ${footnoteHtml}
  `;

  if (!prefersReducedMotion && steps.length > 0) {
    const allRowsAppearedTime = (steps.length - 1) * 600 + 450;
    steps.forEach((_, idx) => {
      const timer = setTimeout(() => {
        const ind = document.getElementById(`plan-indicator-${idx}`);
        if (ind) ind.classList.add('completed');
      }, allRowsAppearedTime + (idx * 500));
      planCircleTimers.push(timer);
    });
  }
}

/**
 * Handle attack_ended event:
 * - Return status line to "All quiet on the network." (green)
 * - Shift chart line color back to olive
 * - Re-enable Launch Attack button
 * - Keep Recognition and Cover Story content visible
 */
function handleAttackEnded(msg) {
  isAttackActive = false;

  const attackBtn = document.getElementById('launch-attack-btn');
  if (attackBtn) attackBtn.disabled = false;

  const statusTextEl = document.getElementById('network-status-text');
  const statusDotEl = document.getElementById('network-status-dot');

  if (statusTextEl && statusDotEl) {
    statusTextEl.textContent = 'All quiet on the network.';
    statusTextEl.classList.remove('status-disconnected');
    statusDotEl.classList.remove('disconnected');
  }

  // Shift Chart back to calm olive
  if (trafficChart) {
    trafficChart.data.datasets[0].borderColor = '#6B705C';
    trafficChart.data.datasets[0].backgroundColor = 'rgba(107, 112, 92, 0.12)';
    trafficChart.data.datasets[0].pointHoverBackgroundColor = '#6B705C';
    trafficChart.update('none');
  }
}

/**
 * Update hero status line and indicator dot based on connection state
 */
function updateNetworkStatus(isConnected) {
  if (isAttackActive) return; // Keep attack status while attack is active

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
 * Handle report event (Module 6 / Stage 6):
 * - Fills the "Incident Report" section as an editorial magazine feature
 * - Headline with serif styling: "The Gate Was <em>Secured</em>"
 * - Tag pill: "Gemini" (olive) or "Template" (terracotta), plus formatted timestamp
 * - Pull quote taken from report's first sentence, framed between hairlines
 * - Paragraphs with drop cap on initial character, fading in one by one
 * - Plain TEXT only (textContent) to prevent injection
 */
function handleReportMessage(msg) {
  const headlineEl = document.getElementById('incident-report-headline');
  if (headlineEl) {
    headlineEl.innerHTML = 'The Gate Was <em>Secured</em>';
  }

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
    if (firstSentence) {
      pullquoteEl.textContent = `“${firstSentence}.”`;
    }
    if (pullquoteWrap) {
      pullquoteWrap.classList.add('editorial-hairlines');
    }
  }
}

/**
 * Handle resolved event (Stage 6):
 * - Status line: "Threat blocked. All quiet on the network." (calm green)
 * - Chart returns to olive as traffic falls back to calm
 * - Cover Story glass card gains calm "Resolved" tag in olive
 * - Plan circles in "III. The Plan" are all ticked
 * - Refresh Back Issues list
 */
function handleResolvedMessage(msg) {
  isAttackActive = false;

  const attackBtn = document.getElementById('launch-attack-btn');
  if (attackBtn) attackBtn.disabled = false;

  const statusTextEl = document.getElementById('network-status-text');
  const statusDotEl = document.getElementById('network-status-dot');

  if (statusTextEl && statusDotEl) {
    statusTextEl.textContent = 'Threat blocked. All quiet on the network.';
    statusTextEl.classList.remove('status-disconnected');
    statusDotEl.classList.remove('disconnected');
  }

  // Return Chart to calm olive
  if (trafficChart) {
    trafficChart.data.datasets[0].borderColor = '#6B705C';
    trafficChart.data.datasets[0].backgroundColor = 'rgba(107, 112, 92, 0.12)';
    trafficChart.data.datasets[0].pointHoverBackgroundColor = '#6B705C';
    trafficChart.update('none');
  }

  // Cover Story gains calm "Resolved" tag in olive
  const resolvedTag = document.getElementById('cover-story-resolved-tag');
  if (resolvedTag) {
    resolvedTag.style.display = 'inline-block';
  }

  // Ensure all plan step indicators are ticked
  document.querySelectorAll('.plan-step-indicator').forEach(el => {
    el.classList.add('completed');
  });

  // Refresh back issues list
  loadBackIssues();
}

/**
 * Handle reset event (Stage 6):
 * - Clear Cover Story, Recognition, Probability, Plan, and Report back to placeholders
 * - Enable Launch Attack button
 * - Set status line to "All quiet on the network."
 * - Return chart to calm olive
 * - Refresh Back Issues list
 */
function handleResetMessage(msg) {
  isAttackActive = false;

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

  // Reset Recognition
  const recognitionBody = document.getElementById('recognition-body');
  if (recognitionBody) {
    recognitionBody.innerHTML = `
      <p>Signature classification distinguishes mundane automated probes from tailored intrusions targeting private infrastructure.</p>
    `;
  }

  // Reset Probability & Plan
  resetProbabilityColumn();
  resetPlanColumn();

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
}

