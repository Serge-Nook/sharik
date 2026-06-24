'use strict';

const $ = (id) => document.getElementById(id);

let devices = [];
let scanning = false;
let sortKey = 'ip';
let sortDir = 1;

const el = {
  range: $('range'),
  concurrency: $('concurrency'),
  pingTimeout: $('pingTimeout'),
  resolveNames: $('resolveNames'),
  scanPorts: $('scanPorts'),
  portTimeout: $('portTimeout'),
  portTimeoutWrap: $('portTimeoutWrap'),
  ports: $('ports'),
  portsRow: $('portsRow'),
  scanBtn: $('scanBtn'),
  cancelBtn: $('cancelBtn'),
  exportBtn: $('exportBtn'),
  clearBtn: $('clearBtn'),
  localBtn: $('localBtn'),
  aboutBtn: $('aboutBtn'),
  progressFill: $('progressFill'),
  progressText: $('progressText'),
  filter: $('filter'),
  countBadge: $('countBadge'),
  resultsBody: $('resultsBody'),
  emptyState: $('emptyState'),
  footerInfo: $('footerInfo'),
};

function ipToInt(ip) {
  const p = String(ip).split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );
}

function render() {
  const q = el.filter.value.trim().toLowerCase();
  let list = devices.slice();

  if (q) {
    list = list.filter((d) =>
      [d.ip, d.hostname, d.mac, d.vendor, (d.ports || []).join(' ')]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q))
    );
  }

  list.sort((a, b) => {
    let av = a[sortKey];
    let bv = b[sortKey];
    if (sortKey === 'ip') { av = ipToInt(a.ip); bv = ipToInt(b.ip); }
    else if (sortKey === 'time') { av = a.time == null ? Infinity : a.time; bv = b.time == null ? Infinity : b.time; }
    else if (sortKey === 'ports') { av = (a.ports || []).length; bv = (b.ports || []).length; }
    else { av = String(av || '').toLowerCase(); bv = String(bv || '').toLowerCase(); }
    if (av < bv) return -1 * sortDir;
    if (av > bv) return 1 * sortDir;
    return 0;
  });

  el.resultsBody.innerHTML = list
    .map((d) => {
      const ports = (d.ports || []).map((p) => `<span class="port-chip">${p}</span>`).join(' ') || '<span class="muted">—</span>';
      const time = d.time != null ? `${d.time} мс` : '<span class="muted">—</span>';
      return `<tr>
        <td class="ip-cell mono"><span class="dot"></span>${escapeHtml(d.ip)}</td>
        <td>${d.hostname ? escapeHtml(d.hostname) : '<span class="muted">—</span>'}</td>
        <td class="mono">${d.mac ? escapeHtml(d.mac) : '<span class="muted">—</span>'}</td>
        <td>${d.vendor ? escapeHtml(d.vendor) : '<span class="muted">—</span>'}</td>
        <td class="mono">${time}</td>
        <td>${ports}</td>
      </tr>`;
    })
    .join('');

  el.emptyState.style.display = list.length ? 'none' : 'flex';
  el.countBadge.textContent = `${devices.length} устройств`;
  el.exportBtn.disabled = devices.length === 0 || scanning;
}

function setScanning(on) {
  scanning = on;
  el.scanBtn.disabled = on;
  el.cancelBtn.disabled = !on;
  el.clearBtn.disabled = on;
  el.exportBtn.disabled = on || devices.length === 0;
}

async function startScan() {
  const range = el.range.value.trim();
  if (!range) {
    el.progressText.textContent = 'Укажите диапазон IP-адресов.';
    return;
  }
  devices = [];
  render();
  el.emptyState.style.display = 'none';
  setScanning(true);
  el.progressFill.style.width = '0%';
  el.progressText.textContent = 'Подготовка…';

  const portsStr = el.ports.value.trim();
  const ports = portsStr
    ? portsStr.split(/[\s,;]+/).map((p) => parseInt(p, 10)).filter((p) => p > 0 && p < 65536)
    : [];

  const opts = {
    range,
    concurrency: parseInt(el.concurrency.value, 10) || 128,
    pingTimeout: parseInt(el.pingTimeout.value, 10) || 1000,
    resolveNames: el.resolveNames.checked,
    scanPorts: el.scanPorts.checked,
    ports,
    portTimeout: parseInt(el.portTimeout.value, 10) || 600,
  };

  try {
    const res = await window.sharik.startScan(opts);
    const verb = res.cancelled ? 'Остановлено' : 'Завершено';
    el.progressFill.style.width = '100%';
    el.progressText.textContent = `${verb}: проверено ${res.total} адресов, найдено ${res.alive} устройств.`;
  } catch (e) {
    el.progressText.textContent = 'Ошибка: ' + (e && e.message ? e.message : e);
  } finally {
    setScanning(false);
    render();
  }
}

// IPC subscriptions
window.sharik.onDevice((d) => {
  devices.push(d);
  render();
});

window.sharik.onProgress((p) => {
  const pct = p.total ? Math.round((p.completed / p.total) * 100) : 0;
  el.progressFill.style.width = pct + '%';
  el.progressText.textContent = `Сканирование… ${p.completed} / ${p.total} (${pct}%) · найдено ${p.alive}`;
});

// Event wiring
el.scanBtn.addEventListener('click', startScan);
el.cancelBtn.addEventListener('click', () => {
  window.sharik.cancelScan();
  el.progressText.textContent = 'Останавливаю…';
});
el.clearBtn.addEventListener('click', () => {
  devices = [];
  el.progressFill.style.width = '0%';
  el.progressText.textContent = 'Готов к сканированию';
  render();
});
el.exportBtn.addEventListener('click', async () => {
  const res = await window.sharik.exportCsv(devices);
  if (res.saved) el.progressText.textContent = 'Сохранено: ' + res.filePath;
});
el.aboutBtn.addEventListener('click', () => window.sharik.showAbout());
el.filter.addEventListener('input', render);

el.scanPorts.addEventListener('change', () => {
  const on = el.scanPorts.checked;
  el.portsRow.style.display = on ? 'flex' : 'none';
  el.portTimeoutWrap.style.display = on ? 'flex' : 'none';
});

el.range.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !scanning) startScan();
});

el.localBtn.addEventListener('click', async () => {
  const ranges = await window.sharik.getLocalRanges();
  if (ranges && ranges.length) {
    el.range.value = ranges[0].cidr;
    el.progressText.textContent = `Локальная сеть: ${ranges[0].iface} (${ranges[0].address})`;
  } else {
    el.progressText.textContent = 'Локальная сеть не обнаружена.';
  }
});

document.querySelectorAll('th[data-sort]').forEach((th) => {
  th.addEventListener('click', () => {
    const key = th.getAttribute('data-sort');
    if (sortKey === key) sortDir *= -1;
    else { sortKey = key; sortDir = 1; }
    render();
  });
});

(async () => {
  const info = await window.sharik.appInfo();
  el.footerInfo.textContent = `${info.name} v${info.version}`;
})();

render();
