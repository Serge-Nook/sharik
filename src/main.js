'use strict';

const { app, BrowserWindow, ipcMain, dialog, Menu, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const scanner = require('./scanner');

const APP_TITLE = 'Шарик — сканер IP-адресов';
const AUTHOR = 'Горшков Сергей Владимирович';

let mainWindow = null;
let currentScan = { cancelled: false, running: false };

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 820,
    minHeight: 520,
    title: APP_TITLE,
    backgroundColor: '#0f1420',
    icon: resolveIcon(),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  buildMenu();
  // mainWindow.webContents.openDevTools();
}

function resolveIcon() {
  const candidates = [
    path.join(__dirname, '..', 'build', 'icons', '512x512.png'),
    path.join(__dirname, '..', 'build', 'icon.png'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return undefined;
}

function buildMenu() {
  const template = [
    {
      label: 'Файл',
      submenu: [
        { label: 'Выход', role: 'quit' },
      ],
    },
    {
      label: 'Вид',
      submenu: [
        { role: 'reload', label: 'Обновить' },
        { role: 'toggleDevTools', label: 'Инструменты разработчика' },
        { type: 'separator' },
        { role: 'resetZoom', label: 'Масштаб 100%' },
        { role: 'zoomIn', label: 'Увеличить' },
        { role: 'zoomOut', label: 'Уменьшить' },
        { role: 'togglefullscreen', label: 'Полный экран' },
      ],
    },
    {
      label: 'Справка',
      submenu: [
        {
          label: 'О программе',
          click: showAbout,
        },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function showAbout() {
  dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'О программе',
    message: 'Шарик',
    detail:
      `Продвинутый сканер IP-адресов\n\n` +
      `Версия: ${app.getVersion()}\n` +
      `Автор: ${AUTHOR}\n\n` +
      `Сканирует диапазон IPv4-адресов и показывает найденные устройства\n` +
      `и информацию о них: IP, имя хоста, MAC, производитель,\n` +
      `время отклика и открытые порты.`,
    buttons: ['OK'],
  });
}

// ---------- IPC ----------
ipcMain.handle('get-local-ranges', () => scanner.getLocalRanges());
ipcMain.handle('app-info', () => ({ name: 'Шарик', version: app.getVersion(), author: AUTHOR }));
ipcMain.handle('show-about', () => showAbout());

ipcMain.handle('scan-cancel', () => {
  currentScan.cancelled = true;
  return true;
});

ipcMain.handle('scan-start', async (event, opts) => {
  if (currentScan.running) throw new Error('Сканирование уже выполняется');

  let targets;
  try {
    targets = scanner.parseTargets(opts.range);
  } catch (e) {
    throw new Error(e.message);
  }

  const concurrency = Math.max(1, Math.min(512, opts.concurrency || 128));
  const pingTimeout = Math.max(200, Math.min(10000, opts.pingTimeout || 1000));
  const doPorts = !!opts.scanPorts;
  const ports = (opts.ports && opts.ports.length ? opts.ports : scanner.COMMON_PORTS);
  const portTimeout = Math.max(100, Math.min(5000, opts.portTimeout || 600));
  const resolveNames = opts.resolveNames !== false;

  currentScan = { cancelled: false, running: true };
  const sender = event.sender;

  // Prime ARP cache by reading it after pings; here just read existing table.
  let arp = await scanner.getArpTable();

  const dnsLib = require('dns');
  const dnsReverse = (ip) =>
    new Promise((resolve) => {
      dnsLib.reverse(ip, (err, names) => resolve(err || !names ? '' : names[0]));
    });

  let aliveCount = 0;

  const worker = async (ip) => {
    if (currentScan.cancelled) return null;
    const ping = await scanner.pingHost(ip, pingTimeout);
    let alive = ping.alive;
    let openPorts = [];

    if (doPorts) {
      openPorts = await scanner.scanPorts(ip, ports, portTimeout);
      if (!alive && openPorts.length > 0) alive = true; // host up even if ICMP blocked
    }

    if (!alive) return null;

    aliveCount++;
    let hostname = '';
    if (resolveNames) {
      try { hostname = await dnsReverse(ip); } catch (e) { hostname = ''; }
    }

    let mac = arp[ip] || '';
    if (!mac) {
      // refresh arp once more; ping should have populated the cache
      const fresh = await scanner.getArpTable();
      arp = Object.assign(arp, fresh);
      mac = arp[ip] || '';
    }
    const vendor = scanner.vendorFromMac(mac);

    const device = {
      ip,
      status: 'up',
      hostname,
      mac,
      vendor,
      time: ping.time,
      ports: openPorts,
    };
    if (!sender.isDestroyed()) sender.send('scan-device', device);
    return device;
  };

  const onProgress = (completed, total) => {
    if (!sender.isDestroyed()) {
      sender.send('scan-progress', { completed, total, alive: aliveCount });
    }
  };

  try {
    const results = await scanner.runPool(targets, worker, concurrency, onProgress);
    const devices = results.filter(Boolean);
    return {
      total: targets.length,
      alive: devices.length,
      cancelled: currentScan.cancelled,
      devices,
    };
  } finally {
    currentScan.running = false;
  }
});

ipcMain.handle('export-csv', async (event, devices) => {
  const { canceled, filePath } = await dialog.showSaveDialog(mainWindow, {
    title: 'Экспорт результатов',
    defaultPath: 'sharik-scan.csv',
    filters: [{ name: 'CSV', extensions: ['csv'] }],
  });
  if (canceled || !filePath) return { saved: false };
  const header = ['IP', 'Статус', 'Имя хоста', 'MAC', 'Производитель', 'Отклик (мс)', 'Открытые порты'];
  const rows = devices.map((d) => [
    d.ip,
    d.status,
    d.hostname || '',
    d.mac || '',
    d.vendor || '',
    d.time != null ? d.time : '',
    (d.ports || []).join(' '),
  ]);
  const csv = [header, ...rows]
    .map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(','))
    .join('\r\n');
  fs.writeFileSync(filePath, '\ufeff' + csv, 'utf8');
  return { saved: true, filePath };
});

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
