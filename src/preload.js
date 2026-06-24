'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sharik', {
  getLocalRanges: () => ipcRenderer.invoke('get-local-ranges'),
  appInfo: () => ipcRenderer.invoke('app-info'),
  showAbout: () => ipcRenderer.invoke('show-about'),
  startScan: (opts) => ipcRenderer.invoke('scan-start', opts),
  cancelScan: () => ipcRenderer.invoke('scan-cancel'),
  exportCsv: (devices) => ipcRenderer.invoke('export-csv', devices),
  onDevice: (cb) => ipcRenderer.on('scan-device', (_e, d) => cb(d)),
  onProgress: (cb) => ipcRenderer.on('scan-progress', (_e, p) => cb(p)),
});
