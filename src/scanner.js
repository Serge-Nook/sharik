'use strict';

const { spawn } = require('child_process');
const net = require('net');
const dns = require('dns');
const fs = require('fs');
const path = require('path');
const os = require('os');

const dnsReverse = require('util').promisify(dns.reverse);

let ouiMap = null;
function loadOui() {
  if (ouiMap) return ouiMap;
  try {
    const p = path.join(__dirname, '..', 'assets', 'oui.json');
    ouiMap = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (e) {
    ouiMap = {};
  }
  return ouiMap;
}

// ---------- IP helpers ----------
function ipToInt(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    throw new Error('Некорректный IP: ' + ip);
  }
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

// Parse user input into a list of IPv4 addresses.
// Supports: single IP, CIDR (a.b.c.d/n), range (a.b.c.d-a.b.c.d or a.b.c.d-last octet),
// and comma/space separated combinations of the above.
function parseTargets(input) {
  if (!input || !input.trim()) throw new Error('Пустой диапазон');
  const out = [];
  const seen = new Set();
  const push = (n) => {
    const ip = intToIp(n >>> 0);
    if (!seen.has(ip)) {
      seen.add(ip);
      out.push(ip);
    }
  };
  const tokens = input.split(/[\s,;]+/).filter(Boolean);
  for (const token of tokens) {
    if (token.includes('/')) {
      const [base, bitsStr] = token.split('/');
      const bits = parseInt(bitsStr, 10);
      if (Number.isNaN(bits) || bits < 0 || bits > 32) throw new Error('Некорректная маска: ' + token);
      const baseInt = ipToInt(base);
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      const network = (baseInt & mask) >>> 0;
      const broadcast = (network | (~mask >>> 0)) >>> 0;
      let start = network;
      let end = broadcast;
      if (bits <= 30) {
        // exclude network and broadcast addresses
        start = (network + 1) >>> 0;
        end = (broadcast - 1) >>> 0;
      }
      for (let n = start; n <= end; n++) push(n);
    } else if (token.includes('-')) {
      const [a, b] = token.split('-');
      const startInt = ipToInt(a.trim());
      let endInt;
      if (b.includes('.')) {
        endInt = ipToInt(b.trim());
      } else {
        // last-octet shorthand: 192.168.1.1-254
        const lastOctet = parseInt(b.trim(), 10);
        if (Number.isNaN(lastOctet) || lastOctet < 0 || lastOctet > 255) throw new Error('Некорректный диапазон: ' + token);
        endInt = ((startInt >>> 8) << 8) + lastOctet;
        endInt = endInt >>> 0;
      }
      if (endInt < startInt) throw new Error('Конец диапазона меньше начала: ' + token);
      for (let n = startInt; n <= endInt; n++) push(n);
    } else {
      push(ipToInt(token.trim()));
    }
  }
  if (out.length > 65536) throw new Error('Слишком большой диапазон (>65536 адресов)');
  return out;
}

// ---------- Ping ----------
function pingHost(ip, timeoutMs) {
  return new Promise((resolve) => {
    const isWin = process.platform === 'win32';
    let args;
    if (isWin) {
      args = ['-n', '1', '-w', String(timeoutMs), ip];
    } else if (process.platform === 'darwin') {
      args = ['-c', '1', '-W', String(timeoutMs), ip];
    } else {
      // linux: -W is in seconds
      const secs = Math.max(1, Math.ceil(timeoutMs / 1000));
      args = ['-c', '1', '-W', String(secs), ip];
    }
    let stdout = '';
    let done = false;
    let child;
    const finish = (alive, time) => {
      if (done) return;
      done = true;
      resolve({ alive, time });
    };
    try {
      child = spawn('ping', args, { windowsHide: true });
    } catch (e) {
      return finish(false, null);
    }
    const killTimer = setTimeout(() => {
      try { child.kill(); } catch (e) {}
      finish(false, null);
    }, timeoutMs + 1500);

    child.stdout.on('data', (d) => { stdout += d.toString(); });
    child.on('error', () => { clearTimeout(killTimer); finish(false, null); });
    child.on('close', (code) => {
      clearTimeout(killTimer);
      if (code === 0) {
        const m = stdout.match(/time[=<]\s*([\d.]+)\s*ms/i);
        const time = m ? parseFloat(m[1]) : null;
        finish(true, time);
      } else {
        finish(false, null);
      }
    });
  });
}

// ---------- TCP port check ----------
function checkPort(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (open) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, ip);
  });
}

async function scanPorts(ip, ports, timeoutMs) {
  const open = [];
  await Promise.all(
    ports.map(async (port) => {
      if (await checkPort(ip, port, timeoutMs)) open.push(port);
    })
  );
  return open.sort((a, b) => a - b);
}

// ---------- ARP table (MAC) ----------
function getArpTable() {
  return new Promise((resolve) => {
    const table = {};
    if (process.platform === 'linux') {
      try {
        const data = fs.readFileSync('/proc/net/arp', 'utf8');
        const lines = data.split('\n').slice(1);
        for (const line of lines) {
          const cols = line.trim().split(/\s+/);
          if (cols.length >= 4) {
            const ip = cols[0];
            const mac = cols[3];
            if (mac && mac !== '00:00:00:00:00:00') table[ip] = mac.toUpperCase();
          }
        }
        return resolve(table);
      } catch (e) {
        // fall through to arp command
      }
    }
    let out = '';
    let child;
    try {
      child = spawn('arp', ['-a'], { windowsHide: true });
    } catch (e) {
      return resolve(table);
    }
    child.stdout.on('data', (d) => { out += d.toString(); });
    child.on('error', () => resolve(table));
    child.on('close', () => {
      const macRe = /([0-9a-f]{2}[:-]){5}[0-9a-f]{2}/i;
      const ipRe = /(\d{1,3}\.){3}\d{1,3}/;
      for (const line of out.split('\n')) {
        const ipM = line.match(ipRe);
        const macM = line.match(macRe);
        if (ipM && macM) {
          table[ipM[0]] = macM[0].replace(/-/g, ':').toUpperCase();
        }
      }
      resolve(table);
    });
  });
}

function vendorFromMac(mac) {
  if (!mac) return '';
  const map = loadOui();
  const key = mac.replace(/[:-]/g, '').toUpperCase().slice(0, 6);
  return map[key] || '';
}

// ---------- Concurrency pool ----------
async function runPool(items, worker, concurrency, onProgress) {
  const results = new Array(items.length);
  let index = 0;
  let completed = 0;
  async function next() {
    while (index < items.length) {
      const i = index++;
      results[i] = await worker(items[i], i);
      completed++;
      if (onProgress) onProgress(completed, items.length);
    }
  }
  const runners = [];
  const n = Math.min(concurrency, items.length);
  for (let k = 0; k < n; k++) runners.push(next());
  await Promise.all(runners);
  return results;
}

// ---------- Local interfaces (helper for UI defaults) ----------
function getLocalRanges() {
  const ifaces = os.networkInterfaces();
  const ranges = [];
  for (const name of Object.keys(ifaces)) {
    for (const addr of ifaces[name]) {
      if (addr.family === 'IPv4' && !addr.internal) {
        const cidr = addr.cidr || `${addr.address}/24`;
        ranges.push({ iface: name, address: addr.address, cidr, mac: (addr.mac || '').toUpperCase() });
      }
    }
  }
  return ranges;
}

const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443];

module.exports = {
  parseTargets,
  pingHost,
  scanPorts,
  checkPort,
  getArpTable,
  vendorFromMac,
  runPool,
  getLocalRanges,
  ipToInt,
  intToIp,
  COMMON_PORTS,
};
