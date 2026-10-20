/* Standalone GitHub Pages presentation mode — no server or login required. */
document.addEventListener('DOMContentLoaded', () => {
  const date = new Intl.DateTimeFormat('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' }).format(new Date());
  document.getElementById('today-date-dashboard').textContent = date;
  document.getElementById('agent-display-name').textContent = 'Presentation Viewer';
  document.getElementById('agent-monogram').textContent = 'PV';

  const values = { pps: 248, size: 512, blocked: 18 };
  const paint = () => {
    values.pps = Math.max(180, values.pps + Math.round((Math.random() - 0.5) * 50));
    document.getElementById('stat-pps').textContent = values.pps;
    document.getElementById('stat-avg-size').textContent = `${values.size} B`;
    document.getElementById('stat-blocked').textContent = values.blocked;
  };
  paint(); setInterval(paint, 1500);

  const canvas = document.getElementById('traffic-chart');
  if (canvas && window.Chart) {
    const chart = new Chart(canvas, { type: 'line', data: { labels: Array.from({ length: 18 }, () => ''), datasets: [{ data: Array.from({ length: 18 }, () => 200 + Math.round(Math.random() * 90)), borderColor: '#6B705C', backgroundColor: 'rgba(107,112,92,.12)', fill: true, tension: .35, pointRadius: 0 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { display: false }, y: { display: false } } } });
    setInterval(() => { chart.data.datasets[0].data.shift(); chart.data.datasets[0].data.push(values.pps); chart.update('none'); }, 1500);
  }

  const button = document.getElementById('launch-attack-btn');
  const label = document.getElementById('launch-attack-label');
  button.addEventListener('click', () => {
    values.pps = 1420; values.blocked = 96; paint();
    label.textContent = 'Demo Attack Detected'; button.disabled = true;
    document.getElementById('network-status-text').textContent = 'Simulation contained — perimeter secure.';
    setTimeout(() => { label.textContent = 'Launch Attack'; button.disabled = false; values.blocked = 18; }, 3500);
  });
  document.getElementById('reset-demo-btn').addEventListener('click', () => { values.pps = 248; values.blocked = 18; paint(); });
});
