const metricCards = document.querySelectorAll('[data-metric]');
const lastUpdate = document.querySelector('#last-update');

async function updateMetrics() {
  const response = await fetch('/api/metrics', { cache: 'no-store' });
  const metrics = await response.json();

  metricCards.forEach((card) => {
    const metric = card.dataset.metric;
    const value = metrics[metric];
    const valueElement = card.querySelector('.metric-value');
    const track = card.querySelector('.metric-track i');

    if (metric === 'files') {
      valueElement.textContent = value.changed === 0 ? 'OK' : `${value.changed} CHANGED`;
      card.querySelector('#file-check-detail').textContent = `${value.checked} FILES / ${value.duration_ns} ns`;
      card.classList.toggle('file-alert', value.changed > 0);
    } else if (metric === 'architecture' || metric === 'os') {
      valueElement.textContent = value;
    } else if (metric === 'latency') {
      valueElement.textContent = `${value} ns`;
    } else if (metric === 'internet') {
      valueElement.textContent = `${value} Mbps`;
    } else {
      valueElement.textContent = `${value}%`;
    }
    if (track) {
      track.style.width = `${metric === 'internet' ? Math.min(100, value / 2) : value}%`;
    }
  });

  lastUpdate.textContent = `${new Date().toLocaleTimeString('en-GB')} / ${metrics.interface}`;
}

updateMetrics().catch(() => {
  lastUpdate.textContent = 'BACKEND UNAVAILABLE';
});
setInterval(updateMetrics, 1000);