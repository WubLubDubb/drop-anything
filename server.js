'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
// 部署在 nginx/Caddy 等反向代理后面时设为 1，从 X-Forwarded-For 取真实 IP
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
// 是否允许经服务器中转文件数据。默认关闭：服务器只转发配对信令和文字等小消息，文件只能直连
const RELAY = process.env.RELAY === '1';
const PUBLIC_DIR = path.join(__dirname, 'public');
// 可选的 HTTPS 端口（自签名证书即可）：浏览器只在 HTTPS 页面允许申请摄像头权限，
// 而有了该权限，WebRTC 才会使用真实内网 IP，局域网直连才可能成功
const HTTPS_PORT = Number(process.env.HTTPS_PORT) || 0;
const TLS_KEY = process.env.TLS_KEY || path.join(__dirname, 'certs/key.pem');
const TLS_CERT = process.env.TLS_CERT || path.join(__dirname, 'certs/cert.pem');

// 中转帧格式：[12 字节对端 id][负载]，与前端 ID_LEN 保持一致
const ID_LEN = 12;
const MAX_FRAME = 256 * 1024;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.json': 'application/json',
  '.webmanifest': 'application/manifest+json',
};

function iceServers() {
  const list = [];
  const stun = (process.env.STUN_URLS || 'stun:stun.cloudflare.com:3478,stun:stun.l.google.com:19302')
    .split(',').map(s => s.trim()).filter(Boolean);
  if (stun.length) list.push({ urls: stun });
  if (process.env.TURN_URLS) {
    list.push({
      urls: process.env.TURN_URLS.split(',').map(s => s.trim()),
      username: process.env.TURN_USERNAME,
      credential: process.env.TURN_CREDENTIAL,
    });
  }
  return list;
}

// ---------- 静态文件 ----------

function serveStatic(req, res) {
  const url = new URL(req.url, 'http://localhost');
  let rel = decodeURIComponent(url.pathname);
  if (rel.endsWith('/')) rel += 'index.html';
  const file = path.join(PUBLIC_DIR, path.normalize(rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(403).end();
    return;
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    });
    res.end(data);
  });
}

// ---------- 设备与房间 ----------

const ADJECTIVES = ['蓝色', '橙色', '安静', '勇敢', '快乐', '聪明', '温柔', '敏捷', '闪亮', '慵懒', '好奇', '淡定', '机灵', '热情', '神秘', '自由'];
const ANIMALS = ['海豚', '狐狸', '熊猫', '企鹅', '考拉', '水獭', '鲸鱼', '猫头鹰', '刺猬', '松鼠', '小鹿', '海豹', '柴犬', '兔子', '鹦鹉', '浣熊'];

const pick = arr => arr[crypto.randomInt(arr.length)];
const randomId = () => crypto.randomBytes(9).toString('base64url'); // 12 个字符

/** @type {Map<string, Client>} */
const clients = new Map();

function clientIp(req) {
  let ip = req.socket.remoteAddress || '';
  if (TRUST_PROXY && req.headers['x-forwarded-for']) {
    ip = String(req.headers['x-forwarded-for']).split(',')[0].trim();
  }
  return ip;
}

function isPrivateIp(ip) {
  if (ip.includes(':')) return ip === '::1' || /^f[cd]/i.test(ip) || /^fe[89ab]/i.test(ip);
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

// 出口网络：同一公网 IPv4，或同一 IPv6 /64 前缀。
// 服务器部署在局域网内（如树莓派）时，客户端都是内网地址，统一视为同一出口，再靠内网网段区分
function networkKey(ip) {
  ip = ip.replace(/%.*$/, '');
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (isPrivateIp(ip)) return 'private';
  if (!ip.includes(':')) return ip;
  const [head, tail] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const full = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  return full.slice(0, 4).map(x => parseInt(x || '0', 16).toString(16)).join(':') + '::/64';
}

// 客户端上报的内网网段标识至少有一个相同（开启局域网直连后才会上报）。
// 设备可能有多个网卡（如手机的 Wi-Fi 和蜂窝网络），所以每台设备可以上报多个网段
const shareLan = (a, b) => [...a.lans].some(tag => b.lans.has(tag));

// 同一局域网：网段相同，且出口网络相同
function sameLan(a, b) {
  return a.net === b.net && shareLan(a, b);
}

// 网段相同但出口不同（iCloud 隐私转发、VPN、代理，或一方走 IPv6）：可能是同一局域网，也可能只是网段撞了。
// 服务器只把对方作为候选告诉双方，由客户端试着直连，确认走的是内网地址后才显示
function lanCandidate(a, b) {
  return a.net !== b.net && shareLan(a, b);
}

const MAX_CANDIDATES = 8;

function visible(a, b) {
  return a !== b && a.ready && b.ready && (shareLan(a, b) || (a.room !== null && a.room === b.room));
}

function send(client, msg) {
  if (client.ws.readyState === client.ws.OPEN) client.ws.send(JSON.stringify(msg));
}

function sendPeers(client) {
  const peers = [];
  const candidates = [];
  for (const other of clients.values()) {
    if (!visible(client, other)) continue;
    const peer = {
      id: other.id,
      name: other.name,
      device: other.device,
      sameLan: sameLan(client, other),
      sameRoom: client.room !== null && other.room === client.room,
      lanCandidate: lanCandidate(client, other),
    };
    if (peer.lanCandidate && !peer.sameRoom) candidates.push([other.joined, peer]);
    else peers.push(peer);
  }
  // 候选只取最近加入的几个，避免常见网段（如 192.168.1.0/24）撞上的设备太多
  candidates.sort((x, y) => y[0] - x[0]);
  peers.push(...candidates.slice(0, MAX_CANDIDATES).map(([, peer]) => peer));
  send(client, { type: 'peers', peers });
}

// 通知所有与给定网络、房间或网段相关的设备刷新列表
function refresh(nets, rooms, tags = []) {
  for (const c of clients.values()) {
    if (!c.ready) continue;
    if (nets.includes(c.net) || (c.room !== null && rooms.includes(c.room)) || tags.some(t => c.lans.has(t))) sendPeers(c);
  }
}

// 房间号由客户端从配对码派生（单向哈希），服务器看不到配对码，也就无法解密房间内的信令
function setRoom(client, room) {
  const old = client.room;
  client.room = room;
  send(client, { type: 'room', room });
  refresh([client.net], [old, room].filter(Boolean));
}

// ---------- WebSocket ----------

const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME });

// HTTP 与 HTTPS 共用同一份设备列表
function attach(server) {
  server.on('upgrade', (req, socket, head) => {
    if (new URL(req.url, 'http://localhost').pathname !== '/ws') {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
  });
  return server;
}

wss.on('connection', (ws, req) => {
  const client = {
    id: randomId(),
    name: pick(ADJECTIVES) + pick(ANIMALS),
    device: '未知设备',
    net: networkKey(clientIp(req)),
    lans: new Set(),
    room: null,
    joined: Date.now(),
    ready: false,
    alive: true,
    ws,
  };
  clients.set(client.id, client);
  send(client, { type: 'welcome', id: client.id, name: client.name, iceServers: iceServers(), relay: RELAY });

  ws.on('pong', () => { client.alive = true; });

  ws.on('message', (data, isBinary) => {
    if (isBinary) return relay(client, data);
    let msg;
    try { msg = JSON.parse(data); } catch { return; }
    switch (msg.type) {
      case 'intro':
        client.device = String(msg.device || '').slice(0, 40) || '未知设备';
        client.ready = true;
        refresh([client.net], [client.room].filter(Boolean), [...client.lans]);
        break;
      case 'lan': {
        const old = [...client.lans];
        client.lans = new Set((Array.isArray(msg.tags) ? msg.tags : [])
          .filter(t => /^[0-9a-f]{32}$/.test(t)).slice(0, 8));
        refresh([client.net], [], [...old, ...client.lans]);
        break;
      }
      case 'join-room':
        if (/^[0-9a-f]{32}$/.test(msg.room)) setRoom(client, msg.room);
        break;
      case 'leave-room':
        if (client.room) setRoom(client, null);
        break;
      case 'signal': {
        const target = clients.get(msg.to);
        if (target && visible(client, target)) send(target, { type: 'signal', from: client.id, data: msg.data });
        break;
      }
    }
  });

  ws.on('close', () => {
    clients.delete(client.id);
    refresh([client.net], [client.room].filter(Boolean), [...client.lans]);
  });
});

// 中转消息：把 [目标 id][负载] 改写成 [来源 id][负载] 后转发
function relay(client, data) {
  if (!RELAY || data.length <= ID_LEN) return;
  const target = clients.get(data.toString('latin1', 0, ID_LEN));
  if (!target || !visible(client, target) || target.ws.readyState !== target.ws.OPEN) return;
  Buffer.from(client.id, 'latin1').copy(data, 0);
  target.ws.send(data, { binary: true });
}

// 清理掉线但未正常关闭的连接（手机锁屏、切网络等）
setInterval(() => {
  for (const c of clients.values()) {
    if (!c.alive) { c.ws.terminate(); continue; }
    c.alive = false;
    c.ws.ping();
  }
}, 30000);

attach(http.createServer(serveStatic)).listen(PORT, HOST, () => {
  console.log(`drop-anything listening on http://${HOST}:${PORT}`);
});

if (HTTPS_PORT) {
  const tls = { key: fs.readFileSync(TLS_KEY), cert: fs.readFileSync(TLS_CERT) };
  attach(https.createServer(tls, serveStatic)).listen(HTTPS_PORT, HOST, () => {
    console.log(`drop-anything listening on https://${HOST}:${HTTPS_PORT}`);
  });
}
