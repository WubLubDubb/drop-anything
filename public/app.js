'use strict';

// 每块略小于 64 KB，保证 Safari 等 max-message-size 为 64 KB 的实现也能发送
const CHUNK_SIZE = 64000;
const MAX_IN_FLIGHT = 64;          // 未确认的块数上限（约 4 MB）
const ACK_EVERY = 8;
const RTC_TIMEOUT = 8000;          // 建立直连的超时
const ACK_TIMEOUT = 30000;
const ID_LEN = 12;                 // 与 server.js 保持一致
const HIGH_WATER = 8 * 1024 * 1024;
const HEARTBEAT = 30000;           // 反向代理和 Cloudflare 会断开长时间无数据的 WebSocket
const MAX_TEXT_BYTES = 60000;      // 文字作为单条消息发送，需小于 64 KB
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // 去掉易混淆的 0/O、1/I/L
const CODE_LEN = 8;                // 31^8 ≈ 2^40
const KDF_ITERATIONS = 200000;
const QR_SCRIPT = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';

const params = new URLSearchParams(location.search);
const FORCE_RELAY = params.has('relay');      // 调试用：?relay 强制走中转
const RTC_SUPPORTED = 'RTCPeerConnection' in window;

const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = id => document.getElementById(id);

const state = {
  me: null,
  iceServers: [],
  relay: false,
  roomCode: null,     // 配对码，只保存在本机
  roomId: null,       // 由配对码派生，发给服务器用于配对
  roomKey: null,      // 由配对码派生的 AES-GCM 密钥
  lanDirect: false,
  lanSubnets: [],
  peers: new Map(),   // id -> 对端信息
  links: new Map(),   // id -> Link
};

/** 发送中的文件，等待对端确认：fid -> { acked, wake, done, fail } */
const outgoing = new Map();
/** 正在接收的文件：peerId -> 接收状态 */
const incoming = new Map();
/** 网段相同、出口不同的候选设备：已探测过的，和确认走内网直连的 */
const probedLan = new Set();
const verifiedLan = new Set();

let ws = null;
let heartbeat = null;

// ---------- 工具 ----------

function randomId() {
  const b = crypto.getRandomValues(new Uint8Array(9));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_');
}

function formatSize(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 ** 2) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 ** 3) return (n / 1024 ** 2).toFixed(1) + ' MB';
  return (n / 1024 ** 3).toFixed(2) + ' GB';
}

function deviceLabel() {
  const ua = navigator.userAgent;
  const os = /iPhone/.test(ua) ? 'iPhone'
    : /iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1) ? 'iPad'
    : /Android/.test(ua) ? 'Android'
    : /Mac OS X/.test(ua) ? 'Mac'
    : /Windows/.test(ua) ? 'Windows'
    : /Linux/.test(ua) ? 'Linux' : '设备';
  const browser = /Edg\//.test(ua) ? 'Edge'
    : /MicroMessenger/.test(ua) ? '微信'
    : /Firefox\//.test(ua) ? 'Firefox'
    : /Chrome\//.test(ua) ? 'Chrome'
    : /Safari\//.test(ua) ? 'Safari' : '浏览器';
  return `${os} · ${browser}`;
}

let toastTimer;
function toast(text) {
  const el = $('toast');
  el.textContent = text;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3000);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const toHex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');

function toB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function fromB64(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// ---------- 配对码与端到端加密 ----------
// 配对码只在设备之间传递（手动输入、扫码，或链接中 # 之后的部分），不会发给服务器。
// 由它派生出两样东西：房间号（发给服务器，用于把设备分到一组）和 AES-GCM 密钥（加密房间内的信令）。
// 房间号是单向哈希，服务器反推不出配对码，因此既读不到也伪造不了房间内的信令，
// 也就无法冒充对方或对直连做中间人攻击；文件本身走 WebRTC，由 DTLS 加密。

function newCode() {
  let code = '';
  while (code.length < CODE_LEN) {
    for (const b of crypto.getRandomValues(new Uint8Array(16))) {
      // 248 = 31 × 8，丢弃更大的值以避免取模偏差
      if (b < 248 && code.length < CODE_LEN) code += CODE_ALPHABET[b % CODE_ALPHABET.length];
    }
  }
  return code;
}

function normalizeCode(input) {
  const code = String(input || '').toUpperCase().replace(/[\s-]/g, '');
  if (code.length !== CODE_LEN || [...code].some(c => !CODE_ALPHABET.includes(c))) return null;
  return code;
}

const formatCode = code => code.slice(0, 4) + '-' + code.slice(4);

async function deriveRoom(code) {
  const base = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode('drop-anything/room/v1'), iterations: KDF_ITERATIONS },
    base, 384));
  const key = await crypto.subtle.importKey('raw', bits.slice(16), 'AES-GCM', false, ['encrypt', 'decrypt']);
  return { id: toHex(bits.slice(0, 16)), key };
}

// 发送方、接收方 id 作为附加数据参与认证，密文无法被转给别人或冒充别人
const aad = (from, to) => enc.encode(`${from}>${to}`);

async function encryptBytes(key, bytes, from, to) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(from, to) }, key, bytes));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv);
  out.set(ct, 12);
  return out;
}

async function decryptBytes(key, data, from, to) {
  const params = { name: 'AES-GCM', iv: data.subarray(0, 12), additionalData: aad(from, to) };
  return new Uint8Array(await crypto.subtle.decrypt(params, key, data.subarray(12)));
}

/** 与该设备通信时使用的密钥：同在一个房间才有 */
function keyFor(peerId) {
  return state.roomKey && state.peers.get(peerId)?.sameRoom ? state.roomKey : null;
}

/** 只通过房间认识的设备，必须使用加密消息，未加密的可能是服务器伪造的 */
function requiresEncryption(peerId) {
  const peer = state.peers.get(peerId);
  return !!peer?.sameRoom && !peer.sameLan;
}

// ---------- 帧格式：[类型 1 字节][内容]，0 = JSON 控制消息，1 = 文件数据块，2 = 加密后的帧（仅中转） ----------

function jsonFrame(obj) {
  const body = enc.encode(JSON.stringify(obj));
  const frame = new Uint8Array(body.length + 1);
  frame[0] = 0;
  frame.set(body, 1);
  return frame;
}

function chunkFrame(buf) {
  const frame = new Uint8Array(buf.byteLength + 1);
  frame[0] = 1;
  frame.set(new Uint8Array(buf), 1);
  return frame;
}

// ---------- 服务器连接 ----------

function connect() {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
  const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
  ws = new WebSocket(proto + location.host + '/ws');
  ws.binaryType = 'arraybuffer';

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: 'intro', device: deviceLabel() }));
    clearInterval(heartbeat);
    heartbeat = setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send('ping'); }, HEARTBEAT);
    sendLanTag();
    if (state.roomId) wsSend({ type: 'join-room', room: state.roomId });
  };

  ws.onmessage = e => {
    if (e.data === 'pong') return;
    if (typeof e.data === 'string') onServerMessage(JSON.parse(e.data));
    else onRelayFrame(e.data);
  };

  ws.onclose = () => {
    clearInterval(heartbeat);
    setStatus(false);
    for (const link of state.links.values()) link.close();
    state.links.clear();
    state.peers.clear();
    renderPeers();
    failAllTransfers('与服务器的连接断开');
    setTimeout(connect, 2000);
  };
}

function wsSend(msg) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

function onServerMessage(msg) {
  switch (msg.type) {
    case 'welcome':
      state.me = msg;
      state.iceServers = msg.iceServers;
      state.relay = !!msg.relay;
      $('my-name').textContent = msg.name;
      $('my-device').textContent = deviceLabel();
      setStatus(true);
      break;
    case 'peers':
      updatePeers(msg.peers);
      break;
    case 'signal':
      getLink(msg.from).onSignal(msg.data);
      break;
    case 'error':
      toast(msg.message);
      break;
  }
}

function updatePeers(list) {
  const ids = new Set(list.map(p => p.id));
  for (const id of state.peers.keys()) {
    if (ids.has(id)) continue;
    state.links.get(id)?.close();
    state.links.delete(id);
    incoming.get(id)?.ui.fail('对方已离开');
    incoming.delete(id);
    probedLan.delete(id);
    verifiedLan.delete(id);
  }
  state.peers = new Map(list.map(p => [p.id, p]));
  renderPeers();
  for (const p of list) if (p.lanCandidate && !p.sameRoom) probeLan(p.id);
}

/** 候选设备是否显示：同一出口的局域网设备、同一房间的设备直接显示，候选设备要先确认能走内网直连 */
function isShown(peer) {
  return !peer.lanCandidate || peer.sameRoom || verifiedLan.has(peer.id);
}

// ---------- 中转（经服务器 WebSocket） ----------

async function relaySend(peerId, frame) {
  while (ws.bufferedAmount > HIGH_WATER) {
    if (ws.readyState !== WebSocket.OPEN) throw new Error('与服务器的连接断开');
    await sleep(20);
  }
  const key = keyFor(peerId);
  if (key) {
    const sealed = await encryptBytes(key, frame, state.me.id, peerId);
    frame = new Uint8Array(sealed.length + 1);
    frame[0] = 2;
    frame.set(sealed, 1);
  }
  if (ws.readyState !== WebSocket.OPEN) throw new Error('与服务器的连接断开');
  const out = new Uint8Array(ID_LEN + frame.length);
  out.set(enc.encode(peerId), 0);
  out.set(frame, ID_LEN);
  ws.send(out);
}

function onRelayFrame(buf) {
  const from = dec.decode(new Uint8Array(buf, 0, ID_LEN));
  const payload = new Uint8Array(buf, ID_LEN);
  const link = getLink(from);
  // 解密是异步的，按到达顺序逐个处理
  link.relayIn = link.relayIn.then(async () => {
    let frame = payload;
    if (frame[0] === 2) {
      if (!state.roomKey) return;
      frame = await decryptBytes(state.roomKey, frame.subarray(1), from, state.me.id);
    } else if (requiresEncryption(from)) {
      return;
    }
    handleFrame(from, frame, f => relaySend(from, f), 'relay');
  }).catch(err => console.warn('中转数据解密失败', err));
}

// ---------- 与单个对端的连接：WebRTC 直连优先，失败则中转 ----------

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

class Link {
  constructor(peerId) {
    this.peerId = peerId;
    this.rtcFailed = FORCE_RELAY || !RTC_SUPPORTED;
    this.pc = null;          // 我方发起的连接
    this.cid = null;
    this.dc = null;
    this.connecting = null;
    this.inbound = new Map(); // 对方发起的连接：cid -> RTCPeerConnection
    this.signals = Promise.resolve();
    this.outSignals = Promise.resolve();
    this.relayIn = Promise.resolve();
    this.sendQueue = Promise.resolve();
  }

  /**
   * 返回本次发送使用的通道。直连已建立就用直连；
   * 服务器允许中转时立即走中转，同时在后台尝试直连；不允许时等待直连，连不上则报错。
   */
  async transport() {
    if (this.dc && this.dc.readyState === 'open') return p2pTransport(this.dc);
    if (state.relay) {
      this.warmUp();
      return { kind: 'relay', send: frame => relaySend(this.peerId, frame) };
    }
    this.rtcFailed = !RTC_SUPPORTED; // 没有中转可退，每次发送都重新尝试直连
    this.warmUp();
    await this.connecting;
    if (this.dc && this.dc.readyState === 'open') return p2pTransport(this.dc);
    throw new Error(window.isSecureContext && !state.lanDirect
      ? '无法直连。请在任一设备上点「开启局域网直连」，并确认两台设备在同一局域网'
      : '无法直连，请确认两台设备在同一局域网');
  }

  /** 尝试建立直连；失败则标记，在允许中转时此后一直用中转 */
  warmUp() {
    if (this.rtcFailed || this.connecting || (this.dc && this.dc.readyState === 'open')) return;
    this.connecting = this.openRtc()
      .catch(err => {
        console.warn('WebRTC 直连失败：', err);
        this.rtcFailed = true;
        this.closeOutbound();
      })
      .finally(() => { this.connecting = null; });
  }

  openRtc() {
    this.closeOutbound();
    return new Promise((resolve, reject) => {
      const cid = randomId();
      const pc = new RTCPeerConnection({ iceServers: state.iceServers });
      const dc = pc.createDataChannel('drop', { ordered: true });
      dc.binaryType = 'arraybuffer';
      dc.bufferedAmountLowThreshold = 1024 * 1024;
      this.pc = pc;
      this.cid = cid;

      const timer = setTimeout(() => reject(new Error('直连超时')), RTC_TIMEOUT);
      dc.onopen = () => { clearTimeout(timer); this.dc = dc; resolve(); };
      dc.onclose = () => { if (this.dc === dc) this.dc = null; };
      dc.onmessage = e => handleFrame(this.peerId, new Uint8Array(e.data), async f => dc.send(f), 'p2p');
      pc.onicecandidate = e => { if (e.candidate) this.signal({ cid, candidate: e.candidate }); };
      pc.onconnectionstatechange = () => {
        if (pc.connectionState === 'failed') { clearTimeout(timer); reject(new Error('直连失败')); }
      };
      pc.createOffer()
        .then(offer => pc.setLocalDescription(offer))
        .then(() => this.signal({ cid, sdp: pc.localDescription }))
        .catch(err => { clearTimeout(timer); reject(err); });
    });
  }

  signal(data) {
    // 加密是异步的，排队发送以保证 SDP 先于 ICE candidate 到达
    this.outSignals = this.outSignals.then(async () => {
      const key = keyFor(this.peerId);
      const payload = key
        ? { e: toB64(await encryptBytes(key, enc.encode(JSON.stringify(data)), state.me.id, this.peerId)) }
        : data;
      wsSend({ type: 'signal', to: this.peerId, data: payload });
    }).catch(err => console.warn('信令发送失败', err));
  }

  onSignal(data) {
    // 按顺序处理，避免 ICE candidate 先于 SDP 被应用
    this.signals = this.signals
      .then(() => this.openSignal(data))
      .then(plain => plain && this.applySignal(plain))
      .catch(err => console.warn('信令处理失败', err));
  }

  async openSignal(data) {
    if (data?.e) {
      if (!state.roomKey) return null;
      const plain = await decryptBytes(state.roomKey, fromB64(data.e), this.peerId, state.me.id);
      return JSON.parse(dec.decode(plain));
    }
    if (requiresEncryption(this.peerId)) throw new Error('拒绝未加密的信令');
    return data;
  }

  async applySignal(data) {
    if (data.retry) {
      resetRtc(this.peerId);
      return;
    }
    const { cid, sdp, candidate } = data;
    if (cid === this.cid && this.pc) {
      if (sdp) await this.pc.setRemoteDescription(sdp);
      if (candidate) await this.pc.addIceCandidate(candidate);
      return;
    }
    let pc = this.inbound.get(cid);
    if (!pc) {
      if (!sdp || !RTC_SUPPORTED) return;
      pc = new RTCPeerConnection({ iceServers: state.iceServers });
      this.inbound.set(cid, pc);
      pc.onicecandidate = e => { if (e.candidate) this.signal({ cid, candidate: e.candidate }); };
      pc.ondatachannel = e => {
        const dc = e.channel;
        dc.binaryType = 'arraybuffer';
        dc.onmessage = ev => handleFrame(this.peerId, new Uint8Array(ev.data), async f => dc.send(f), 'p2p');
      };
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
        this.signal({ cid, sdp: pc.localDescription });
      }
    }
    if (candidate) await pc.addIceCandidate(candidate);
  }

  closeOutbound() {
    this.pc?.close();
    this.pc = null;
    this.cid = null;
    this.dc = null;
  }

  close() {
    this.closeOutbound();
    for (const pc of this.inbound.values()) pc.close();
    this.inbound.clear();
    for (const [fid, p] of outgoing) if (p.peerId === this.peerId) p.fail(new Error('对方已离开'));
  }

  enqueue(task) {
    this.sendQueue = this.sendQueue.then(task, task);
    return this.sendQueue;
  }
}

// ---------- 发送 ----------

function sendFiles(peerId, files) {
  const link = getLink(peerId);
  for (const file of files) {
    const ui = transferUI('out', file.name, file.size, peerName(peerId));
    ui.setStatus('排队中');
    link.enqueue(() => sendFile(link, file, ui).catch(err => {
      console.error(err);
      ui.fail(err.message || '发送失败');
    }));
  }
}

async function sendFile(link, file, ui) {
  ui.setStatus('正在建立直连…');
  const tr = await link.transport();
  ui.setVia(tr.kind);

  const fid = randomId();
  const pending = { peerId: link.peerId, acked: 0, wake: null, error: null };
  const finished = new Promise((resolve, reject) => {
    pending.done = resolve;
    pending.fail = err => { pending.error = err; reject(err); pending.wake?.(); };
  });
  finished.catch(() => {});
  outgoing.set(fid, pending);

  try {
    await tr.send(jsonFrame({ t: 'file', fid, name: file.name, size: file.size, mime: file.type }));
    const started = performance.now();
    let sent = 0;
    let index = 0;
    while (sent < file.size) {
      while (index - pending.acked >= MAX_IN_FLIGHT) {
        await waitForAck(pending);
      }
      const buf = await file.slice(sent, sent + CHUNK_SIZE).arrayBuffer();
      await tr.send(chunkFrame(buf));
      sent += buf.byteLength;
      index++;
      ui.setProgress(sent / file.size, sent / ((performance.now() - started) / 1000));
    }
    await tr.send(jsonFrame({ t: 'end', fid }));
    ui.setStatus('等待对方确认…');
    await withTimeout(finished, ACK_TIMEOUT);
    ui.complete('已发送');
  } finally {
    outgoing.delete(fid);
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
  for (const inc of incoming.values()) inc.ui.fail(reason);
  incoming.clear();
}

async function sendText(peerId, text) {
  const frame = jsonFrame({ t: 'text', text });
  if (frame.length > MAX_TEXT_BYTES) return toast('文字太长，请存成文件发送');
  try {
    // 和文件一样走直连，内容不经过服务器
    const tr = await getLink(peerId).transport();
    await tr.send(frame);
    toast('已发送');
  } catch (err) {
    toast('发送失败：' + err.message);
  }
}

// ---------- 接收 ----------

function handleFrame(peerId, frame, reply, via) {
  if (frame[0] === 1) return onChunk(peerId, frame.subarray(1), reply);
  let msg;
  try { msg = JSON.parse(dec.decode(frame.subarray(1))); } catch { return; }

  switch (msg.t) {
    case 'file': {
      incoming.get(peerId)?.ui.fail('被新的文件打断');
      const ui = transferUI('in', msg.name, msg.size, peerName(peerId));
      ui.setStatus('接收中');
      ui.setVia(via);
      incoming.set(peerId, { ...msg, parts: [], received: 0, count: 0, started: performance.now(), ui });
      break;
    }
    case 'end': {
      const inc = incoming.get(peerId);
      if (!inc || inc.fid !== msg.fid) return;
      incoming.delete(peerId);
      if (inc.received !== inc.size) {
        inc.ui.fail(`文件不完整（${formatSize(inc.received)} / ${formatSize(inc.size)}）`);
        return;
      }
      const blob = new Blob(inc.parts, { type: inc.mime || 'application/octet-stream' });
      inc.ui.received(blob, inc.name);
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
      showReceivedText(peerName(peerId), String(msg.text));
      break;
  }
}

function onChunk(peerId, data, reply) {
  const inc = incoming.get(peerId);
  if (!inc) return;
  inc.parts.push(data.slice());
  inc.received += data.byteLength;
  inc.count++;
  inc.ui.setProgress(inc.received / inc.size, inc.received / ((performance.now() - inc.started) / 1000));
  if (inc.count % ACK_EVERY === 0) reply(jsonFrame({ t: 'ack', fid: inc.fid, n: inc.count })).catch(() => {});
}

// ---------- 局域网直连 ----------

// 浏览器默认把 WebRTC 里的内网 IP 隐藏成 xxx.local，需要组播解析，校园网屏蔽组播时直连就会失败。
// 页面获得摄像头权限后，浏览器会改用真实内网 IP。这里只为拿到权限，拿到后立即关闭摄像头。
// 拿到真实内网 IP 后，再上报所在网段的哈希，服务器据此把同一局域网的设备自动分到一组。
async function enableLanDirect(silent = false) {
  if (!navigator.mediaDevices?.getUserMedia) {
    if (!silent) toast('需要通过 https:// 打开本页才能开启');
    return;
  }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    stream.getTracks().forEach(t => t.stop());
  } catch (err) {
    if (!silent) toast('未获得摄像头权限：' + err.message);
    return;
  }
  state.lanDirect = true;
  state.lanSubnets = await detectSubnets();
  try { localStorage.setItem('lanDirect', '1'); } catch {}
  renderLan();
  sendLanTag();
  // 双方都忘掉之前的直连失败，重新尝试
  for (const id of state.peers.keys()) {
    resetRtc(id);
    getLink(id).signal({ retry: true });
  }
  if (!silent) {
    toast(state.lanSubnets.length ? '已开启，同一局域网的设备会自动出现' : '已开启，但浏览器仍隐藏了内网 IP，请用配对码配对');
  }
}

// 之前开启过且摄像头权限仍在时，打开页面自动恢复（不会弹窗）
async function restoreLanDirect() {
  try {
    if (localStorage.getItem('lanDirect') !== '1') return;
    const perm = await navigator.permissions?.query({ name: 'camera' });
    if (perm?.state === 'granted') await enableLanDirect(true);
  } catch {}
}

const isPrivateV4 = ip => /^(10|192\.168|172\.(1[6-9]|2\d|3[01]))(\.\d{1,3}){2,3}$/.test(ip);

/**
 * 从 WebRTC 的 host candidate 里取本机所有内网 IP，换算成网段（192.168.x.x 按 /24，其余按 /16）。
 * 设备可能同时有多个网卡（手机的 Wi-Fi 和蜂窝网络、电脑的有线和无线），全部上报
 */
async function detectSubnets() {
  const pc = new RTCPeerConnection();
  pc.createDataChannel('probe');
  const ips = [];
  const gathered = new Promise(resolve => {
    pc.onicecandidate = e => {
      if (!e.candidate) return resolve();
      const parts = e.candidate.candidate.split(' ');
      if (parts[7] === 'host' && isPrivateV4(parts[4])) ips.push(parts[4]);
    };
    setTimeout(resolve, 2000);
  });
  await pc.setLocalDescription(await pc.createOffer());
  await gathered;
  pc.close();
  const subnets = ips.map(ip => {
    const p = ip.split('.');
    return ip.startsWith('192.168.') ? `${p[0]}.${p[1]}.${p[2]}.0/24` : `${p[0]}.${p[1]}.0.0/16`;
  });
  return [...new Set(subnets)].sort();
}

// 只上报网段的哈希，服务器只需要比较是否相同
async function sendLanTag() {
  if (!state.lanSubnets.length) return;
  const tags = await Promise.all(state.lanSubnets.map(async subnet => {
    const digest = await crypto.subtle.digest('SHA-256', enc.encode('drop-anything/lan/v1|' + subnet));
    return toHex(new Uint8Array(digest).slice(0, 16));
  }));
  wsSend({ type: 'lan', tags });
}

// 网段相同但出口 IP 不同（iCloud 隐私转发、VPN 等）时，先试着直连，
// 只有选中的连接两端都是内网地址，才确认是同一局域网
async function probeLan(peerId) {
  if (probedLan.has(peerId)) return;
  probedLan.add(peerId);
  const link = getLink(peerId);
  link.rtcFailed = !RTC_SUPPORTED;
  link.warmUp();
  await link.connecting;
  if (!state.peers.has(peerId) || !link.pc || !(await isLanPath(link.pc))) return;
  verifiedLan.add(peerId);
  renderPeers();
}

async function isLanPath(pc) {
  const stats = await pc.getStats();
  let pair = null;
  stats.forEach(r => { if (r.type === 'transport' && r.selectedCandidatePairId) pair = stats.get(r.selectedCandidatePairId); });
  if (!pair) stats.forEach(r => { if (r.type === 'candidate-pair' && r.nominated && r.state === 'succeeded') pair = r; });
  if (!pair) return false;
  const local = stats.get(pair.localCandidateId);
  const remote = stats.get(pair.remoteCandidateId);
  const addr = remote?.address || remote?.ip || '';
  if (local?.candidateType !== 'host' || !['host', 'prflx'].includes(remote?.candidateType)) return false;
  // 地址为空或是 xxx.local，说明是经 mDNS 解析的，只有同一局域网内才解析得到
  return isPrivateV4(addr) || (remote.candidateType === 'host' && (!addr || addr.endsWith('.local')));
}

function resetRtc(peerId) {
  const link = getLink(peerId);
  if (link.dc && link.dc.readyState === 'open') return;
  link.rtcFailed = FORCE_RELAY || !RTC_SUPPORTED;
  link.warmUp();
}

function renderLan() {
  const btn = $('lan-enable');
  btn.hidden = !RTC_SUPPORTED || state.lanDirect;
  $('lan-hint').textContent = state.lanDirect
    ? (state.lanSubnets.length ? `局域网直连已开启（${state.lanSubnets.join('、')}）` : '已开启，但浏览器仍隐藏了内网 IP')
    : window.isSecureContext ? '开启后，同一局域网的设备会自动出现并直连' : '开启局域网直连需要通过 https:// 打开本页';
}

// ---------- 界面 ----------

function setStatus(online) {
  const el = $('status');
  el.className = 'status ' + (online ? 'online' : 'offline');
  el.textContent = online ? '已连接' : '重新连接中…';
}

function peerName(id) {
  return state.peers.get(id)?.name || '对方';
}

// 配对码放在 # 之后，浏览器不会把它发给服务器
function roomLink(code) {
  return `${location.origin}${location.pathname}#room=${code}`;
}

async function joinRoom(code) {
  if (!crypto.subtle) {
    toast('配对需要通过 https:// 打开本页');
    return;
  }
  const { id, key } = await deriveRoom(code);
  state.roomCode = code;
  state.roomId = id;
  state.roomKey = key;
  try { localStorage.setItem('roomCode', code); } catch {}
  wsSend({ type: 'join-room', room: id });
  renderRoom();
}

function leaveRoom() {
  state.roomCode = state.roomId = state.roomKey = null;
  try { localStorage.removeItem('roomCode'); } catch {}
  wsSend({ type: 'leave-room' });
  renderRoom();
}

function renderRoom() {
  $('room-out').hidden = !!state.roomCode;
  $('room-in').hidden = !state.roomCode;
  const qr = $('room-qr');
  qr.innerHTML = '';
  if (!state.roomCode) return;
  $('room-code').textContent = formatCode(state.roomCode);
  if (window.QRCode) {
    new QRCode(qr, { text: roomLink(state.roomCode), width: 120, height: 120, correctLevel: QRCode.CorrectLevel.M });
  } else {
    loadQRCode();
  }
}

// 二维码库按需加载，加载失败不影响其他功能
let qrLoading = false;
function loadQRCode() {
  if (qrLoading) return;
  qrLoading = true;
  const s = document.createElement('script');
  s.src = QR_SCRIPT;
  s.onload = renderRoom;
  document.head.appendChild(s);
}

let fileTarget = null;

function renderPeers() {
  const box = $('peers');
  box.innerHTML = '';
  const shown = [...state.peers.values()].filter(isShown);
  $('empty').hidden = shown.length > 0;
  for (const peer of shown) {
    const card = document.createElement('div');
    card.className = 'card peer';
    card.innerHTML = `
      <div>
        <div class="name"></div>
        <div class="sub"></div>
      </div>
      <div class="badges"></div>
      <div class="row">
        <button data-act="file">发文件</button>
        <button data-act="text" class="secondary">发文字</button>
      </div>`;
    card.querySelector('.name').textContent = peer.name;
    card.querySelector('.sub').textContent = peer.device;
    const badges = card.querySelector('.badges');
    if (peer.sameLan || verifiedLan.has(peer.id)) badges.insertAdjacentHTML('beforeend', '<span class="badge">同一局域网</span>');
    if (peer.sameRoom) badges.insertAdjacentHTML('beforeend', '<span class="badge secure">同一房间 · 已加密</span>');

    // 选文件的同时在后台预先建立直连，选好时多半已经连上
    card.querySelector('[data-act=file]').onclick = () => {
      fileTarget = peer.id;
      getLink(peer.id).warmUp();
      $('file-input').click();
    };
    card.querySelector('[data-act=text]').onclick = () => openTextDialog(peer);

    card.addEventListener('dragenter', () => getLink(peer.id).warmUp());
    card.addEventListener('dragover', e => { e.preventDefault(); card.classList.add('drag'); });
    card.addEventListener('dragleave', () => card.classList.remove('drag'));
    card.addEventListener('drop', e => {
      e.preventDefault();
      card.classList.remove('drag');
      if (e.dataTransfer.files.length) sendFiles(peer.id, [...e.dataTransfer.files]);
    });
    box.appendChild(card);
  }
}

function openTextDialog(peer) {
  const dlg = $('text-dialog');
  $('text-title').textContent = `发送文字给 ${peer.name}`;
  $('text-input').value = '';
  dlg.onclose = () => {
    const text = $('text-input').value;
    if (dlg.returnValue === 'send' && text.trim()) sendText(peer.id, text);
  };
  dlg.returnValue = '';
  dlg.showModal();
}

function showReceivedText(from, text) {
  const dlg = $('recv-dialog');
  $('recv-title').textContent = `来自 ${from} 的文字`;
  const box = $('recv-text');
  box.textContent = '';
  // 纯链接时直接给出可点击的链接
  if (/^https?:\/\/\S+$/.test(text.trim())) {
    const a = document.createElement('a');
    a.href = text.trim();
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = text.trim();
    box.appendChild(a);
  } else {
    box.textContent = text;
  }
  dlg.onclose = () => {
    if (dlg.returnValue === 'copy') {
      navigator.clipboard?.writeText(text).then(() => toast('已复制'), () => toast('复制失败，请手动选择'));
    }
  };
  dlg.returnValue = '';
  dlg.showModal();
}

function transferUI(direction, name, size, peer) {
  $('transfers-section').hidden = false;
  const el = document.createElement('div');
  el.className = 'card transfer';
  el.innerHTML = `
    <div class="top"><span class="fname"></span><span class="meta"></span></div>
    <div class="bar"><div></div></div>
    <div class="foot"><span class="status"></span><span class="right"></span></div>`;
  el.querySelector('.fname').textContent = name;
  el.querySelector('.meta').textContent = `${direction === 'out' ? '发给' : '来自'} ${peer} · ${formatSize(size)}`;
  $('transfers').prepend(el);

  const bar = el.querySelector('.bar > div');
  const status = el.querySelector('.status');
  const right = el.querySelector('.right');
  let via = '';

  return {
    setStatus(text) { status.textContent = text; },
    setVia(kind) {
      via = kind;
      right.className = 'right via-' + kind;
      right.textContent = kind === 'p2p' ? '直连' : '服务器中转';
    },
    setProgress(ratio, speed) {
      bar.style.width = (ratio * 100).toFixed(1) + '%';
      status.textContent = `${(ratio * 100).toFixed(0)}% · ${formatSize(speed || 0)}/s`;
    },
    complete(text) {
      el.classList.add('done');
      bar.style.width = '100%';
      status.textContent = text;
    },
    fail(text) {
      el.classList.add('failed');
      status.textContent = '失败：' + text;
    },
    received(blob, filename) {
      this.complete(via === 'p2p' ? '接收完成 · 直连' : via === 'relay' ? '接收完成 · 服务器中转' : '接收完成');
      const url = URL.createObjectURL(blob);
      right.className = 'right';
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.textContent = '保存';
      right.replaceChildren(a);
      if (blob.type.startsWith('image/')) {
        const img = document.createElement('img');
        img.src = url;
        img.alt = filename;
        el.appendChild(img);
      }
    },
  };
}

// ---------- 事件绑定 ----------

$('file-input').onchange = e => {
  const files = [...e.target.files];
  e.target.value = '';
  if (fileTarget && files.length) sendFiles(fileTarget, files);
};

$('room-join').onclick = () => {
  const code = normalizeCode($('room-input').value);
  if (!code) return toast(`配对码为 ${CODE_LEN} 位字母和数字`);
  $('room-input').value = '';
  joinRoom(code);
};
$('room-input').onkeydown = e => { if (e.key === 'Enter') $('room-join').click(); };
$('lan-enable').onclick = () => enableLanDirect();
renderLan();
$('room-create').onclick = () => joinRoom(newCode());
$('room-leave').onclick = leaveRoom;
$('room-copy').onclick = () => {
  const link = roomLink(state.roomCode);
  navigator.clipboard?.writeText(link).then(() => toast('链接已复制'), () => toast(link));
};

// 手机切回前台时，若连接已断开则立即重连
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && ws && ws.readyState === WebSocket.CLOSED) connect();
});

// 打开配对链接时，从 # 中取出配对码，随后从地址栏移除
const linkCode = normalizeCode(new URLSearchParams(location.hash.slice(1)).get('room'));
if (location.hash) history.replaceState(null, '', location.pathname + location.search);
let savedCode = null;
try { savedCode = normalizeCode(localStorage.getItem('roomCode')); } catch {}
if (linkCode || savedCode) joinRoom(linkCode || savedCode);

connect();
restoreLanDirect();
