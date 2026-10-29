// Cloudflare Workers 版本的配对服务，协议与 ../server.js 相同，前端（../public）原样复用。
// 在线设备列表需要放在同一处，所以所有连接都交给同一个 Durable Object 管理；
// 使用 WebSocket 休眠 API，没有消息时 Durable Object 可以休眠，不占用免费额度。
import { DurableObject } from 'cloudflare:workers';

const ID_LEN = 12; // 与前端 ID_LEN 保持一致
const MAX_CANDIDATES = 8;
const CLOSE_REPLACED = 4000; // 与 server.js 相同
// 前端每 30 秒发一次心跳；后台标签页的定时器可能被浏览器降到每分钟一次，所以留足余量
const STALE_MS = 120000;
const SWEEP_MS = 60000;

const ADJECTIVES = ['蓝色', '橙色', '安静', '勇敢', '快乐', '聪明', '温柔', '敏捷', '闪亮', '慵懒', '好奇', '淡定', '机灵', '热情', '神秘', '自由'];
const ANIMALS = ['海豚', '狐狸', '熊猫', '企鹅', '考拉', '水獭', '鲸鱼', '猫头鹰', '刺猬', '松鼠', '小鹿', '海豹', '柴犬', '兔子', '鹦鹉', '浣熊'];

const randomInt = n => crypto.getRandomValues(new Uint32Array(1))[0] % n;
const pick = arr => arr[randomInt(arr.length)];

// 由浏览器的设备标识决定名字，同一浏览器重连后名字不变（与 server.js 相同）
const nameFor = key => ADJECTIVES[parseInt(key.slice(0, 2), 16) % ADJECTIVES.length]
  + ANIMALS[parseInt(key.slice(2, 4), 16) % ANIMALS.length];

function randomId() {
  const b = crypto.getRandomValues(new Uint8Array(9));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_'); // 12 个字符
}

function isPrivateIp(ip) {
  if (ip.includes(':')) return ip === '::1' || /^f[cd]/i.test(ip) || /^fe[89ab]/i.test(ip);
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

// 出口网络：同一公网 IPv4，或同一 IPv6 /64 前缀（与 server.js 相同）
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

function iceServers(env) {
  const list = [];
  const stun = (env.STUN_URLS || 'stun:stun.cloudflare.com:3478,stun:stun.l.google.com:19302')
    .split(',').map(s => s.trim()).filter(Boolean);
  if (stun.length) list.push({ urls: stun });
  return list;
}

export default {
  async fetch(request, env) {
    // 静态文件由 Workers 的静态资源功能直接返回，只有 /ws 会进到这里
    if (new URL(request.url).pathname !== '/ws') return env.ASSETS.fetch(request);
    if (request.headers.get('Upgrade') !== 'websocket') return new Response('Expected WebSocket', { status: 426 });
    return env.HUB.get(env.HUB.idFromName('global')).fetch(request);
  },
};

export class Hub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    /** @type {Map<string, object>} id -> 设备信息（含 ws） */
    this.clients = new Map();
    // 从休眠中恢复时，内存是空的，从各连接的附加数据里重建设备列表
    for (const ws of ctx.getWebSockets()) {
      const info = ws.deserializeAttachment();
      if (info && !info.dropped) this.clients.set(info.id, { ...info, ws });
    }
    // 前端的心跳由运行时直接回复，不会唤醒 Durable Object
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }

  async fetch(request) {
    const [clientSide, ws] = Object.values(new WebSocketPair());
    this.ctx.acceptWebSocket(ws);
    const client = {
      id: randomId(),
      name: pick(ADJECTIVES) + pick(ANIMALS),
      device: '未知设备',
      net: networkKey(request.headers.get('CF-Connecting-IP') || ''),
      lans: [],
      room: null,
      joined: Date.now(),
      ready: false,
      ws,
    };
    this.clients.set(client.id, client);
    this.persist(client);
    this.send(client, { type: 'welcome', id: client.id, name: client.name, iceServers: iceServers(this.env), relay: this.env.RELAY === '1' });
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + SWEEP_MS);
    return new Response(null, { status: 101, webSocket: clientSide });
  }

  // 定时清理掉线但没有正常关闭的连接（断网、休眠）。心跳由运行时自动回复，这里读取最后一次回复的时间
  async alarm() {
    const now = Date.now();
    for (const ws of this.ctx.getWebSockets()) {
      const client = this.clientOf(ws);
      if (!client) continue;
      const lastPing = this.ctx.getWebSocketAutoResponseTimestamp(ws)?.getTime() ?? 0;
      if (now - Math.max(lastPing, client.joined) < STALE_MS) continue;
      this.dropClient(client);
      try { ws.close(1001, 'timeout'); } catch {}
    }
    if (this.clients.size) await this.ctx.storage.setAlarm(now + SWEEP_MS);
  }

  /** 把设备信息存进连接的附加数据，休眠后才能恢复 */
  persist(client) {
    const { ws, ...info } = client;
    ws.serializeAttachment(info);
  }

  clientOf(ws) {
    return this.clients.get(ws.deserializeAttachment()?.id);
  }

  send(client, msg) {
    try { client.ws.send(JSON.stringify(msg)); } catch {}
  }

  shareLan(a, b) {
    return a.lans.some(tag => b.lans.includes(tag));
  }

  // 同一局域网：网段相同，且出口网络相同
  sameLan(a, b) {
    return a.net === b.net && this.shareLan(a, b);
  }

  // 网段相同但出口不同（iCloud 隐私转发、VPN、代理，或一方走 IPv6）：只作为候选，由客户端直连确认（与 server.js 相同）
  lanCandidate(a, b) {
    return a.net !== b.net && this.shareLan(a, b);
  }

  visible(a, b) {
    return a !== b && a.ready && b.ready && (this.shareLan(a, b) || (a.room !== null && a.room === b.room));
  }

  sendPeers(client) {
    const peers = [];
    const candidates = [];
    for (const other of this.clients.values()) {
      if (!this.visible(client, other)) continue;
      const peer = {
        id: other.id,
        name: other.name,
        device: other.device,
        sameLan: this.sameLan(client, other),
        sameRoom: client.room !== null && other.room === client.room,
        lanCandidate: this.lanCandidate(client, other),
      };
      if (peer.lanCandidate && !peer.sameRoom) candidates.push([other.joined, peer]);
      else peers.push(peer);
    }
    // 候选只取最近加入的几个，避免常见网段（如 192.168.1.0/24）撞上的设备太多
    candidates.sort((x, y) => y[0] - x[0]);
    peers.push(...candidates.slice(0, MAX_CANDIDATES).map(([, peer]) => peer));
    this.send(client, { type: 'peers', peers });
  }

  // 通知所有与给定网络、房间或网段相关的设备刷新列表
  refresh(nets, rooms, tags = []) {
    for (const c of this.clients.values()) {
      if (!c.ready) continue;
      if (nets.includes(c.net) || (c.room !== null && rooms.includes(c.room)) || tags.some(t => c.lans.includes(t))) this.sendPeers(c);
    }
  }

  setRoom(client, room) {
    const old = client.room;
    client.room = room;
    this.persist(client);
    this.send(client, { type: 'room', room });
    this.refresh([client.net], [old, room].filter(Boolean));
  }

  async webSocketMessage(ws, message) {
    const client = this.clientOf(ws);
    if (!client) return;
    if (typeof message !== 'string') return this.relay(client, message);
    let msg;
    try { msg = JSON.parse(message); } catch { return; }
    switch (msg.type) {
      case 'intro':
        client.device = String(msg.device || '').slice(0, 40) || '未知设备';
        // 没有设备标识的是更新前的旧页面：无法识别重连，不加入列表，提示刷新
        if (!/^[0-9a-f]{32}$/.test(msg.key)) {
          this.send(client, { type: 'error', message: '页面已更新，请刷新' });
          break;
        }
        client.key = msg.key;
        client.name = nameFor(msg.key);
        this.send(client, { type: 'name', name: client.name });
        // 换网络、休眠唤醒后重连时，旧连接往往还没断开，直接替换掉
        for (const other of [...this.clients.values()]) {
          if (other === client || other.key !== client.key) continue;
          this.dropClient(other);
          try { other.ws.close(CLOSE_REPLACED, 'replaced'); } catch {}
        }
        client.ready = true;
        this.persist(client);
        this.refresh([client.net], [client.room].filter(Boolean), client.lans);
        break;
      case 'lan': {
        const old = client.lans;
        client.lans = (Array.isArray(msg.tags) ? msg.tags : []).filter(t => /^[0-9a-f]{32}$/.test(t)).slice(0, 8);
        this.persist(client);
        this.refresh([client.net], [], [...old, ...client.lans]);
        break;
      }
      case 'join-room':
        if (/^[0-9a-f]{32}$/.test(msg.room)) this.setRoom(client, msg.room);
        break;
      case 'leave-room':
        if (client.room) this.setRoom(client, null);
        break;
      case 'signal': {
        const target = this.clients.get(msg.to);
        if (target && this.visible(client, target)) this.send(target, { type: 'signal', from: client.id, data: msg.data });
        break;
      }
    }
  }

  // 中转消息：把 [目标 id][负载] 改写成 [来源 id][负载] 后转发；默认关闭
  relay(client, message) {
    if (this.env.RELAY !== '1' || message.byteLength <= ID_LEN) return;
    const data = new Uint8Array(message);
    const target = this.clients.get(new TextDecoder().decode(data.subarray(0, ID_LEN)));
    if (!target || !this.visible(client, target)) return;
    data.set(new TextEncoder().encode(client.id), 0);
    try { target.ws.send(data); } catch {}
  }

  remove(ws) {
    const client = this.clientOf(ws);
    if (client) this.dropClient(client);
  }

  dropClient(client) {
    // 先标记再移除：连接若没能立即关闭，Durable Object 从休眠恢复时也不会把它加回列表
    try { this.persist({ ...client, dropped: true }); } catch {}
    this.clients.delete(client.id);
    this.refresh([client.net], [client.room].filter(Boolean), client.lans);
  }

  async webSocketClose(ws) {
    this.remove(ws);
    try { ws.close(1000); } catch {}
  }

  async webSocketError(ws) {
    this.remove(ws);
  }
}
