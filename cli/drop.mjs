#!/usr/bin/env node
// Drop Anything 命令行客户端：在没有浏览器的设备（如远程服务器）上收发文件。
// 协议与网页端（public/app.js）相同，只通过配对码与房间内的设备通信，信令全部端到端加密。

import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import WebSocket from 'ws';
import { RTCPeerConnection } from 'node-datachannel/polyfill';
import qrcode from 'qrcode-terminal';

// 以下常量与 public/app.js 保持一致
const CHUNK_SIZE = 64000;
const MAX_IN_FLIGHT = 64;
const ACK_EVERY = 8;
const RTC_TIMEOUT = 8000;
const ACK_TIMEOUT = 30000;
const ID_LEN = 12;
const HIGH_WATER = 8 * 1024 * 1024;
const HEARTBEAT = 30000;
const CLOSE_REPLACED = 4000;
const MAX_TEXT_BYTES = 60000;
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const CODE_LEN = 8;
const KDF_ITERATIONS = 200000;

const USAGE = `用法：
  drop-anything receive [--dir 目录] [选项]           保持在线，接收文件和文字
  drop-anything send <文件...> [--text 文字] [选项]   发给房间里的设备后退出

选项：
  --server URL     配对服务器地址，也可用环境变量 DROP_SERVER
  --code 配对码     加入已有房间（也可传完整的配对链接），也可用环境变量 DROP_CODE；
                   不填则新建房间，并在终端显示配对码和二维码
  --to 名字         send 时只发给该名字的设备（默认发给第一个加入房间的设备）
  --ports A-B      限定直连使用的 UDP 端口范围，便于配置防火墙
  -h, --help       显示帮助`;

const enc = new TextEncoder();
const dec = new TextDecoder();
const { subtle } = globalThis.crypto;

// ---------- 参数 ----------

let args;
try {
  args = parseArgs({
    allowPositionals: true,
    options: {
      server: { type: 'string' },
      code: { type: 'string' },
      dir: { type: 'string' },
      text: { type: 'string' },
      to: { type: 'string' },
      ports: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
  });
} catch (err) {
  exitWith(err.message + '\n\n' + USAGE);
}

const [command, ...files] = args.positionals;
if (args.values.help || !['send', 'receive'].includes(command)) exitWith(USAGE, args.values.help ? 0 : 1);
if (command === 'send' && !files.length && args.values.text === undefined) exitWith('请指定要发送的文件或 --text');
if (command === 'receive' && files.length) exitWith('receive 不接受文件参数，用 --dir 指定保存目录');

const serverInput = args.values.server || process.env.DROP_SERVER;
if (!serverInput) exitWith('请用 --server 或环境变量 DROP_SERVER 指定配对服务器地址');
const server = new URL(/^[a-z]+:\/\//i.test(serverInput) ? serverInput : 'https://' + serverInput);
const WS_URL = (server.protocol === 'http:' ? 'ws://' : 'wss://') + server.host + '/ws';

const SAVE_DIR = path.resolve(args.values.dir || '.');
if (command === 'receive' && !fs.statSync(SAVE_DIR, { throwIfNoEntry: false })?.isDirectory()) {
  exitWith('保存目录不存在：' + SAVE_DIR);
}

const rtcConfig = {};
if (args.values.ports) {
  const m = /^(\d+)-(\d+)$/.exec(args.values.ports);
  if (!m || +m[1] > +m[2] || +m[2] > 65535) exitWith('--ports 格式为 起始-结束，例如 40000-40100');
  rtcConfig.portRangeBegin = +m[1];
  rtcConfig.portRangeEnd = +m[2];
}

const textToSend = args.values.text;
if (textToSend !== undefined && enc.encode(JSON.stringify({ t: 'text', text: textToSend })).length + 1 > MAX_TEXT_BYTES) {
  exitWith('文字太长，请存成文件发送');
}

const sendPaths = [];
for (const f of files) {
  const st = fs.statSync(f, { throwIfNoEntry: false });
  if (!st?.isFile()) exitWith('不是文件：' + f);
  sendPaths.push(path.resolve(f));
}

// ---------- 工具 ----------

function exitWith(message, code = 1) {
  (code ? console.error : console.log)(message);
  process.exit(code);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const toHex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
const randomId = () => Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(9))).toString('base64url');

function formatSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 ** 2) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 ** 3) return (n / 1024 ** 2).toFixed(1) + ' MB';
  return (n / 1024 ** 3).toFixed(2) + ' GB';
}

function deviceLabel() {
  const name = { linux: 'Linux', darwin: 'Mac', win32: 'Windows' }[os.platform()] || os.platform();
  return `${name} · 命令行`;
}

// 进度只占一行，打印其他信息前先清掉
const isTTY = process.stderr.isTTY;
let progressShown = false;
function log(text) {
  if (progressShown) { process.stderr.write('\r\x1b[K'); progressShown = false; }
  console.log(text);
}
let lastProgress = 0;
function progress(label, done, total, started) {
  if (!isTTY) return;
  const now = Date.now();
  if (done < total && now - lastProgress < 200) return;
  lastProgress = now;
  const speed = done / Math.max((now - started) / 1000, 0.001);
  const pct = total ? (done / total * 100).toFixed(0) : '100';
  process.stderr.write(`\r\x1b[K${label}  ${pct}% · ${formatSize(done)} / ${formatSize(total)} · ${formatSize(speed)}/s`);
  progressShown = true;
}

const MIME = {
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp',
  '.heic': 'image/heic', '.svg': 'image/svg+xml', '.pdf': 'application/pdf', '.txt': 'text/plain',
  '.mp4': 'video/mp4', '.mov': 'video/quicktime', '.mp3': 'audio/mpeg', '.zip': 'application/zip',
};

// ---------- 配对码与加密（与网页端相同） ----------

function newCode() {
  let code = '';
  while (code.length < CODE_LEN) {
    for (const b of globalThis.crypto.getRandomValues(new Uint8Array(16))) {
      if (b < 248 && code.length < CODE_LEN) code += CODE_ALPHABET[b % CODE_ALPHABET.length];
    }
  }
  return code;
}

function normalizeCode(input) {
  let raw = String(input || '');
  const fromLink = /#room=([^&]+)/.exec(raw);
  if (fromLink) raw = decodeURIComponent(fromLink[1]);
  const code = raw.toUpperCase().replace(/[\s-]/g, '');
  if (code.length !== CODE_LEN || [...code].some(c => !CODE_ALPHABET.includes(c))) return null;
  return code;
}

const formatCode = code => code.slice(0, 4) + '-' + code.slice(4);

async function deriveRoom(code) {
  const base = await subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode('drop-anything/room/v1'), iterations: KDF_ITERATIONS },
    base, 384));
  const key = await subtle.importKey('raw', bits.slice(16), 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { id: toHex(bits.slice(0, 16)), key };
}

const aad = (from, to) => enc.encode(`${from}>${to}`);

async function encryptBytes(key, bytes, from, to) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(from, to) }, key, bytes));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv);
  out.set(ct, 12);
  return out;
}

async function decryptBytes(key, data, from, to) {
  const params = { name: 'AES-GCM', iv: data.subarray(0, 12), additionalData: aad(from, to) };
  return new Uint8Array(await subtle.decrypt(params, key, data.subarray(12)));
}

function jsonFrame(obj) {
  const body = enc.encode(JSON.stringify(obj));
  const frame = new Uint8Array(body.length + 1);
  frame[0] = 0;
  frame.set(body, 1);
  return frame;
}

// ---------- 状态 ----------

const state = {
  me: null,
  iceServers: [],
  relay: false,
  roomCode: null,
  roomId: null,
  roomKey: null,
  peers: new Map(),   // 只包含同一房间的设备
  links: new Map(),
};

const outgoing = new Map();
const incoming = new Map();
const peerWaiters = new Set();

let ws = null;
let heartbeat = null;
// 每次运行用新的设备标识：同一台机器上同时运行多个实例时不会互相顶替
const DEVICE_KEY = toHex(globalThis.crypto.getRandomValues(new Uint8Array(16)));

// ---------- 服务器连接 ----------

function connect() {
  ws = new WebSocket(WS_URL);
  ws.binaryType = 'arraybuffer';

  ws.on('open', () => {
    ws.send(JSON.stringify({ type: 'intro', device: deviceLabel(), key: DEVICE_KEY }));
    clearInterval(heartbeat);
    heartbeat = setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send('ping'); }, HEARTBEAT);
    wsSend({ type: 'join-room', room: state.roomId });
  });

  ws.on('message', (data, isBinary) => {
    if (isBinary) return onRelayFrame(new Uint8Array(data));
    const text = data.toString();
    if (text === 'pong') return;
    try { onServerMessage(JSON.parse(text)); } catch (err) { console.warn('无法解析服务器消息', err); }
  });

  ws.on('error', err => log('连接服务器出错：' + (err.message || err.code || err.errors?.[0]?.code || err)));

  ws.on('close', code => {
    clearInterval(heartbeat);
    for (const link of state.links.values()) link.close();
    state.links.clear();
    updatePeers([]);
    failAllTransfers('与服务器的连接断开');
    if (code === CLOSE_REPLACED) exitWith('该连接已被替换');
    log('与服务器的连接断开，2 秒后重连…');
    setTimeout(connect, 2000);
  });
}

function wsSend(msg) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

function onServerMessage(msg) {
  switch (msg.type) {
    case 'welcome':
      state.me = msg;
      state.iceServers = msg.iceServers || [];
      state.relay = !!msg.relay;
      break;
    case 'name':
      if (state.me?.name !== msg.name) log(`已连接，本机名字：${msg.name}（${deviceLabel()}）`);
      state.me.name = msg.name;
      break;
    case 'peers':
      // 命令行端不上报网段，只与同一房间的设备通信
      updatePeers(msg.peers.filter(p => p.sameRoom));
      break;
    case 'signal':
      if (state.peers.has(msg.from)) getLink(msg.from).onSignal(msg.data);
      break;
    case 'error':
      log('服务器：' + msg.message);
      break;
  }
}

function updatePeers(list) {
  const ids = new Set(list.map(p => p.id));
  for (const [id, peer] of state.peers) {
    if (ids.has(id)) continue;
    log(`- ${peer.name}（${peer.device}）离开了房间`);
    state.links.get(id)?.close();
    state.links.delete(id);
    abortIncoming(id, '对方已离开');
  }
  for (const p of list) if (!state.peers.has(p.id)) log(`+ ${p.name}（${p.device}）加入了房间`);
  state.peers = new Map(list.map(p => [p.id, p]));
  for (const waiter of peerWaiters) waiter();
}

const peerName = id => state.peers.get(id)?.name || '对方';

// ---------- 中转（仅在服务器开启 RELAY=1 时使用） ----------

async function relaySend(peerId, frame) {
  while (ws.bufferedAmount > HIGH_WATER) {
    if (ws.readyState !== WebSocket.OPEN) throw new Error('与服务器的连接断开');
    await sleep(20);
  }
  const sealed = await encryptBytes(state.roomKey, frame, state.me.id, peerId);
  if (ws.readyState !== WebSocket.OPEN) throw new Error('与服务器的连接断开');
  const out = new Uint8Array(ID_LEN + 1 + sealed.length);
  out.set(enc.encode(peerId), 0);
  out[ID_LEN] = 2;
  out.set(sealed, ID_LEN + 1);
  ws.send(out);
}

function onRelayFrame(buf) {
  if (buf.length <= ID_LEN + 1) return;
  const from = dec.decode(buf.subarray(0, ID_LEN));
  // 房间内的设备之间只接受加密帧，未加密的可能是服务器伪造的
  if (!state.peers.has(from) || buf[ID_LEN] !== 2) return;
  const link = getLink(from);
  link.receive(async () => {
    const frame = await decryptBytes(state.roomKey, buf.subarray(ID_LEN + 1), from, state.me.id);
    await handleFrame(from, frame, f => relaySend(from, f), 'relay');
  });
}

// ---------- 与单个对端的连接 ----------

function p2pTransport(dc) {
  return {
    kind: 'p2p',
    send: async frame => {
      if (dc.readyState !== 'open') throw new Error('直连已断开');
      if (dc.bufferedAmount > HIGH_WATER) {
        await new Promise(r => {
          dc.addEventListener('bufferedamountlow', r, { once: true });
          dc.addEventListener('close', r, { once: true });
        });
        if (dc.readyState !== 'open') throw new Error('直连已断开');
      }
      dc.send(frame);
    },
  };
}

function getLink(peerId) {
  let link = state.links.get(peerId);
  if (!link) {
    link = new Link(peerId);
    state.links.set(peerId, link);
  }
  return link;
}

// 序列化 SDP 和 ICE candidate，只保留浏览器认得的字段
const plainSdp = d => ({ type: d.type, sdp: d.sdp });
function plainCandidate(c) {
  return { candidate: c.candidate.replace(/^a=/, ''), sdpMid: c.sdpMid, sdpMLineIndex: c.sdpMLineIndex };
}

class Link {
  constructor(peerId) {
    this.peerId = peerId;
    this.pc = null;
    this.cid = null;
    this.dc = null;
    this.connecting = null;
    this.inbound = new Map();
    this.signals = Promise.resolve();
    this.outSignals = Promise.resolve();
    this.frames = Promise.resolve();
    this.closed = false;
  }

  /** 收到的帧逐个处理：写文件是异步的，且要等写完再确认，避免占用过多内存 */
  receive(task) {
    this.frames = this.frames.then(task).catch(err => log('处理数据失败：' + err.message));
  }

  async transport() {
    if (this.dc && this.dc.readyState === 'open') return p2pTransport(this.dc);
    if (state.relay) {
      this.warmUp();
      return { kind: 'relay', send: frame => relaySend(this.peerId, frame) };
    }
    this.warmUp();
    await this.connecting;
    if (this.dc && this.dc.readyState === 'open') return p2pTransport(this.dc);
    throw new Error('无法直连。请确认两台设备在同一局域网，或本机有公网 IP 且防火墙放行了 UDP');
  }

  warmUp() {
    if (this.closed || this.connecting || (this.dc && this.dc.readyState === 'open')) return;
    this.connecting = this.openRtc()
      .catch(err => {
        log('直连失败：' + err.message);
        this.closeOutbound();
      })
      .finally(() => { this.connecting = null; });
  }

  newPeerConnection(cid) {
    const pc = new RTCPeerConnection({ ...rtcConfig, iceServers: state.iceServers });
    pc.onicecandidate = e => {
      if (e.candidate?.candidate) this.signal({ cid, candidate: plainCandidate(e.candidate) });
    };
    return pc;
  }

  attachChannel(dc) {
    dc.binaryType = 'arraybuffer';
    dc.onmessage = e => {
      if (typeof e.data === 'string') return;
      const frame = new Uint8Array(e.data);
      this.receive(() => handleFrame(this.peerId, frame, async f => dc.send(f), 'p2p'));
    };
  }

  openRtc() {
    this.closeOutbound();
    return new Promise((resolve, reject) => {
      const cid = randomId();
      const pc = this.newPeerConnection(cid);
      const dc = pc.createDataChannel('drop', { ordered: true });
      dc.bufferedAmountLowThreshold = 1024 * 1024;
      this.attachChannel(dc);
      this.pc = pc;
      this.cid = cid;

      const timer = setTimeout(() => reject(new Error('直连超时')), RTC_TIMEOUT);
      dc.onopen = () => { clearTimeout(timer); this.dc = dc; resolve(); };
      dc.onclose = () => { if (this.dc === dc) this.dc = null; };
      pc.onconnectionstatechange = () => {
        if (pc.connectionState === 'failed') { clearTimeout(timer); reject(new Error('连接失败')); }
      };
      pc.createOffer()
        .then(offer => pc.setLocalDescription(offer))
        .then(() => this.signal({ cid, sdp: plainSdp(pc.localDescription) }))
        .catch(err => { clearTimeout(timer); reject(err); });
    });
  }

  // 只与房间内的设备通信，信令一律加密
  signal(data) {
    this.outSignals = this.outSignals.then(async () => {
      const sealed = await encryptBytes(state.roomKey, enc.encode(JSON.stringify(data)), state.me.id, this.peerId);
      wsSend({ type: 'signal', to: this.peerId, data: { e: Buffer.from(sealed).toString('base64') } });
    }).catch(err => log('信令发送失败：' + err.message));
  }

  onSignal(data) {
    this.signals = this.signals
      .then(async () => {
        if (!data?.e) return; // 拒绝未加密的信令
        const plain = await decryptBytes(state.roomKey, new Uint8Array(Buffer.from(data.e, 'base64')), this.peerId, state.me.id);
        await this.applySignal(JSON.parse(dec.decode(plain)));
      })
      .catch(err => log('信令处理失败：' + err.message));
  }

  async applySignal(data) {
    if (data.retry || this.closed) return;
    const { cid, sdp, candidate } = data;
    if (cid === this.cid && this.pc) {
      if (sdp) await this.pc.setRemoteDescription(sdp);
      if (candidate) await addCandidate(this.pc, candidate);
      return;
    }
    let pc = this.inbound.get(cid);
    if (!pc) {
      if (!sdp) return;
      pc = this.newPeerConnection(cid);
      this.inbound.set(cid, pc);
      pc.ondatachannel = e => this.attachChannel(e.channel);
      pc.onconnectionstatechange = () => {
        if (['failed', 'closed'].includes(pc.connectionState)) {
          pc.close();
          this.inbound.delete(cid);
        }
      };
    }
    if (sdp) {
      await pc.setRemoteDescription(sdp);
      if (sdp.type === 'offer') {
        await pc.setLocalDescription(await pc.createAnswer());
        this.signal({ cid, sdp: plainSdp(pc.localDescription) });
      }
    }
    if (candidate) await addCandidate(pc, candidate);
  }

  closeOutbound() {
    this.pc?.close();
    this.pc = null;
    this.cid = null;
    this.dc = null;
  }

  close() {
    this.closed = true;
    this.closeOutbound();
    for (const pc of this.inbound.values()) pc.close();
    this.inbound.clear();
    for (const p of outgoing.values()) if (p.peerId === this.peerId) p.fail(new Error('对方已离开'));
  }
}

// 浏览器给出的 xxx.local 地址在这里可能解析不了，忽略即可：本机给出的是真实 IP，对方能直接连过来
async function addCandidate(pc, candidate) {
  if (!candidate.candidate) return;
  try { await pc.addIceCandidate(candidate); } catch {}
}

// ---------- 发送 ----------

async function sendFile(link, filePath) {
  const name = path.basename(filePath);
  const fh = await fsp.open(filePath, 'r');
  try {
    const { size } = await fh.stat();
    log(`正在连接 ${peerName(link.peerId)}…`);
    const tr = await link.transport();

    const fid = randomId();
    const pending = { peerId: link.peerId, acked: 0, wake: null, error: null };
    const finished = new Promise((resolve, reject) => {
      pending.done = resolve;
      pending.fail = err => { pending.error = err; reject(err); pending.wake?.(); };
    });
    finished.catch(() => {});
    outgoing.set(fid, pending);

    try {
      const mime = MIME[path.extname(name).toLowerCase()] || '';
      await tr.send(jsonFrame({ t: 'file', fid, name, size, mime }));
      const started = Date.now();
      let sent = 0;
      let index = 0;
      while (sent < size) {
        while (index - pending.acked >= MAX_IN_FLIGHT) await waitForAck(pending);
        // 直接读进帧里，第 0 字节是类型（1 = 文件数据块）
        const frame = new Uint8Array(1 + Math.min(CHUNK_SIZE, size - sent));
        frame[0] = 1;
        const { bytesRead } = await fh.read(frame, 1, frame.length - 1, sent);
        if (bytesRead !== frame.length - 1) throw new Error('读取文件失败，文件可能在发送中被修改');
        await tr.send(frame);
        sent += bytesRead;
        index++;
        progress(`↑ ${name}`, sent, size, started);
      }
      await tr.send(jsonFrame({ t: 'end', fid }));
      await withTimeout(finished, ACK_TIMEOUT);
      log(`✓ 已发送 ${name}（${formatSize(size)}，${tr.kind === 'p2p' ? '直连' : '服务器中转'}）`);
    } finally {
      outgoing.delete(fid);
    }
  } finally {
    await fh.close();
  }
}

function waitForAck(pending) {
  if (pending.error) throw pending.error;
  return withTimeout(new Promise(r => { pending.wake = r; }), ACK_TIMEOUT).then(() => {
    pending.wake = null;
    if (pending.error) throw pending.error;
  });
}

function withTimeout(promise, ms) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('对方长时间无响应')), ms); }),
  ]).finally(() => clearTimeout(timer));
}

function failAllTransfers(reason) {
  for (const p of outgoing.values()) p.fail(new Error(reason));
  for (const id of [...incoming.keys()]) abortIncoming(id, reason);
}

// ---------- 接收 ----------

/** 去掉路径和控制字符，文件只会写进保存目录 */
function safeName(name) {
  let base = path.basename(String(name || '')).replace(/[\x00-\x1f\x7f/\\:*?"<>|]/g, '_').trim();
  if (!base || /^\.+$/.test(base)) base = 'file';
  return base.slice(0, 200);
}

/** 不覆盖已有文件：重名时加上 (1)、(2)… */
function uniquePath(name) {
  const ext = path.extname(name);
  const stem = name.slice(0, name.length - ext.length);
  for (let i = 0; ; i++) {
    const candidate = path.join(SAVE_DIR, i ? `${stem} (${i})${ext}` : name);
    if (!fs.existsSync(candidate) && !fs.existsSync(candidate + '.part')) return candidate;
  }
}

function abortIncoming(peerId, reason) {
  const inc = incoming.get(peerId);
  if (!inc) return;
  incoming.delete(peerId);
  log(`✗ 接收 ${inc.name} 失败：${reason}`);
  inc.fh.close().catch(() => {}).finally(() => fsp.unlink(inc.temp).catch(() => {}));
}

async function handleFrame(peerId, frame, reply, via) {
  if (!state.peers.has(peerId)) return;
  if (frame[0] === 1) return onChunk(peerId, frame.subarray(1), reply);
  let msg;
  try { msg = JSON.parse(dec.decode(frame.subarray(1))); } catch { return; }

  switch (msg.t) {
    case 'file': {
      // 只有 receive 模式保存文件；send 模式下对方发来的文件不接收，对方会提示超时
      if (command !== 'receive') return;
      if (!Number.isSafeInteger(msg.size) || msg.size < 0) return;
      abortIncoming(peerId, '被新的文件打断');
      const final = uniquePath(safeName(msg.name));
      const temp = final + '.part';
      const fh = await fsp.open(temp, 'wx');
      incoming.set(peerId, {
        fid: msg.fid, name: path.basename(final), size: msg.size, final, temp, fh,
        received: 0, count: 0, started: Date.now(), via,
      });
      log(`↓ 正在接收 ${path.basename(final)}（${formatSize(msg.size)}，来自 ${peerName(peerId)}）`);
      break;
    }
    case 'end': {
      const inc = incoming.get(peerId);
      if (!inc || inc.fid !== msg.fid) return;
      if (inc.received !== inc.size) {
        abortIncoming(peerId, `文件不完整（${formatSize(inc.received)} / ${formatSize(inc.size)}）`);
        return;
      }
      incoming.delete(peerId);
      await inc.fh.close();
      const final = fs.existsSync(inc.final) ? uniquePath(path.basename(inc.final)) : inc.final;
      await fsp.rename(inc.temp, final);
      log(`✓ 已保存 ${final}（${inc.via === 'p2p' ? '直连' : '服务器中转'}）`);
      reply(jsonFrame({ t: 'done', fid: msg.fid })).catch(() => {});
      break;
    }
    case 'ack': {
      const p = outgoing.get(msg.fid);
      if (p) { p.acked = msg.n; p.wake?.(); }
      break;
    }
    case 'done':
      outgoing.get(msg.fid)?.done();
      break;
    case 'text':
      log(`💬 来自 ${peerName(peerId)} 的文字：\n${String(msg.text)}`);
      break;
  }
}

async function onChunk(peerId, data, reply) {
  const inc = incoming.get(peerId);
  if (!inc) return;
  if (inc.received + data.byteLength > inc.size) return abortIncoming(peerId, '数据超出文件大小');
  await inc.fh.write(data);
  inc.received += data.byteLength;
  inc.count++;
  progress(`↓ ${inc.name}`, inc.received, inc.size, inc.started);
  if (inc.count % ACK_EVERY === 0) reply(jsonFrame({ t: 'ack', fid: inc.fid, n: inc.count })).catch(() => {});
}

// ---------- 主流程 ----------

/** 等待房间里出现要发送的设备：指定了 --to 时按名字匹配，否则取第一个 */
function waitForPeer() {
  const pick = () => [...state.peers.values()].find(p => !args.values.to || p.name === args.values.to);
  return new Promise(resolve => {
    const check = () => {
      const peer = pick();
      if (!peer) return;
      peerWaiters.delete(check);
      resolve(peer);
    };
    peerWaiters.add(check);
    check();
  });
}

function showRoom(created) {
  const link = `${server.origin}/#room=${state.roomCode}`;
  if (created) {
    log(`配对码：${formatCode(state.roomCode)}`);
    log(`在另一台设备上打开 ${server.origin}，点「加入房间」输入配对码，或扫码：`);
    qrcode.generate(link, { small: true }, qr => log(qr));
  } else {
    log(`已加入房间 ${formatCode(state.roomCode)}`);
  }
}

async function main() {
  const codeInput = args.values.code || process.env.DROP_CODE;
  const code = codeInput ? normalizeCode(codeInput) : newCode();
  if (!code) exitWith(`配对码为 ${CODE_LEN} 位字母和数字`);
  const { id, key } = await deriveRoom(code);
  Object.assign(state, { roomCode: code, roomId: id, roomKey: key });

  showRoom(!codeInput);
  connect();

  process.on('SIGINT', () => {
    for (const id of [...incoming.keys()]) abortIncoming(id, '已退出');
    setTimeout(() => process.exit(130), 100);
  });

  if (command === 'receive') {
    log(`接收的文件会保存到 ${SAVE_DIR}，按 Ctrl+C 退出`);
    return;
  }

  log(args.values.to ? `等待 ${args.values.to} 加入房间…` : '等待对方加入房间…');
  const peer = await waitForPeer();
  const link = getLink(peer.id);
  try {
    for (const file of sendPaths) await sendFile(link, file);
    if (textToSend !== undefined) {
      const tr = await link.transport();
      await tr.send(jsonFrame({ t: 'text', text: textToSend }));
      log(`✓ 已发送文字（${tr.kind === 'p2p' ? '直连' : '服务器中转'}）`);
    }
  } catch (err) {
    log('✗ 发送失败：' + err.message);
    process.exit(1);
  }
  // 留一点时间让最后的数据发出去
  await sleep(300);
  process.exit(0);
}

main().catch(err => exitWith(err.stack || String(err)));
