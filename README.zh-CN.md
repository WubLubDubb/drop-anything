# Drop Anything

[English](README.md) | **简体中文**

在浏览器里给同一局域网的设备发文件和文字，不用装 App、不用注册。**任何局域网都能用，在屏蔽了组播的校园网、企业网里，也能让浏览器之间直连。**

- 📡 **局域网直传**：文件和文字通过 WebRTC 在两台设备之间直接传输，不经过服务器，速度取决于局域网带宽。
- 🏫 **屏蔽组播的网络也能直连**：浏览器默认隐藏内网 IP，靠组播（mDNS）解析；校园网、企业网屏蔽组播时，Snapdrop、PairDrop 这类工具同网段也连不上。这里通过「开启局域网直连」让浏览器使用真实内网 IP。
- 🔍 **只发现自己局域网里的设备**：按内网网段分组，不会像按公网 IP 分组那样，把同一校园网出口下的所有陌生人都列出来。
- 🔐 **配对码端到端加密**：服务器只知道配对码的哈希，读不到、也伪造不了配对设备之间的信令。
- ☁️ **服务器只负责配对**：可以免费部署到 Cloudflare Workers，也可以跑在 VPS 或树莓派上，几乎不占带宽。

## 和 Snapdrop / PairDrop 的区别

| | Snapdrop / PairDrop | Drop Anything |
|---|---|---|
| 设备发现 | 按公网出口 IP 分组。部署在公网时，同一校园网、公司出口下的所有人互相可见；开了 iCloud 隐私转发、VPN 的设备又找不到 | 按内网网段分组；出口 IP 不同时，先直连确认确实在同一局域网再显示 |
| 屏蔽组播的网络 | 同网段也无法直连，只能经 TURN 中转（慢，或者连不上） | 开启局域网直连后直连 |
| 信令安全 | 服务器转发明文信令；PairDrop 的配对密钥由服务器生成 | 配对码只在设备之间传递，房间内信令端到端加密并认证 |
| 直连失败时 | 有 TURN 就经 TURN 中转 | 默认提示失败原因，不中转；可选开启中转（`RELAY=1`） |

PairDrop 功能更丰富（永久配对、多语言、PWA、系统分享菜单等）。如果你的网络不屏蔽组播（多数家用路由器），它同样是很好的选择。

## 使用

1. 两台设备用浏览器打开同一个部署地址。
2. **同一局域网**：两边都点「开启局域网直连」并允许摄像头（只为拿到权限，随即关闭，不会拍摄），对方会自动出现，卡片标「同一局域网」。
3. **想加密验证对方，或自动发现没出现**：一边点「新建房间」，另一边输入 8 位配对码或扫码，卡片标「同一房间 · 已加密」。
4. 点对方卡片上的「发文件」「发文字」，或把文件拖到卡片上。每条传输记录会标明是「直连」还是「服务器中转」。

## 两种找到对方的方式

### 同一局域网：开启局域网直连，自动出现

浏览器默认把 WebRTC 中的内网 IP 隐藏成 `xxx.local`，需要组播解析；校园网（如 NTUSECURE）屏蔽组播时，同一网段的设备也直连不上。点「开启局域网直连」并允许摄像头权限（拿到后立即关闭摄像头），浏览器就会使用真实内网 IP：

1. 同一网段内可以直连（只需一方开启）；
2. 页面算出本机所有内网网段（`192.168.x.x` 按 /24，其余按 /16；手机的 Wi-Fi 和蜂窝网络、电脑的有线和无线各算一个），把它们的哈希发给服务器。至少有一个网段相同的设备会自动出现在列表里（需要双方都开启）：
   - 出口 IP 也相同：直接显示；
   - 出口 IP 不同（iPhone 的 iCloud 隐私转发、VPN、代理，或一方走 IPv6）：先在后台试着直连，确认选中的连接两端都是内网地址后才显示。网段恰好相同的其他地方的设备连不上内网地址，不会出现。每台设备最多同时探测 8 个这类候选。

之后打开页面，若摄像头权限仍在，会自动恢复，不再弹窗。该功能要求页面通过 HTTPS 打开。

### 已实测环境

| 网络 | 设备 | 不开启局域网直连 | 开启后自动发现 | 开启后传输 |
|---|---|---|---|---|
| NTU 校园网 NTUSECURE（屏蔽组播） | iPhone Safari ↔ Mac | ❌ 无法直连 | ✅（两台设备出口 IP 不同，经直连确认后显示） | ✅ 双向直连，文件和文字均正常 |
| 家用路由器（小米） | iPhone Safari ↔ Mac | ✅ 直连（用配对码配对） | ✅ | ✅ 直连，速度快 |

欢迎补充其他网络和浏览器的测试结果。

### 不在同一局域网或需要验证对方：配对码

点「新建房间」生成 8 位配对码（如 `K7PM-Q3XD`），另一台设备输入配对码或扫码加入。注意：不同网段（例如宿舍路由器下的设备与 NTUSECURE 上的设备）之间没有可直连的路径，配对后也传不了，除非开启 `RELAY=1`。

## 加密与安全边界

| 内容 | 保护方式 |
|---|---|
| 文件、文字 | WebRTC DataChannel，DTLS 加密，只在两台设备之间传输 |
| 设备与服务器之间的连接 | 部署成 HTTPS 时为 WSS（TLS） |
| 房间内的信令（SDP、ICE candidate） | 用配对码派生的 AES-256-GCM 密钥端到端加密，并把收发双方 id 作为附加认证数据 |
| 开启中转（`RELAY=1`）时房间内的中转数据 | 同上，逐帧 AES-GCM 加密 |

配对码的处理：

- 配对码只存在于设备上（输入框、二维码、链接中 `#` 之后的部分），浏览器不会把 `#` 之后的内容发给服务器，页面打开后也会把它从地址栏移除。
- 由配对码经 PBKDF2-SHA256（20 万次）派生出 128 位房间号和 256 位 AES 密钥。服务器只拿到房间号，反推不出配对码。
- 配对码共 31⁸ ≈ 2⁴⁰ 种，其他用户无法猜中。即使服务器被攻破，想暴力破解配对码，也需要约 10¹⁷ 次 SHA-256 运算。
- 来自房间内设备的信令必须能用房间密钥解密，否则直接丢弃。服务器因此无法冒充对方，也无法篡改 DTLS 指纹来做中间人攻击。

安全边界：

- **只通过「同一局域网」自动发现的设备**：双方没有共享密钥，信令只受 TLS 保护，所以需要信任服务器（自己部署的服务器通常没问题）。传敏感文件时，建议先用配对码加入同一房间，卡片上会显示「同一房间 · 已加密」。
- 出口 IP 不同的同网段候选设备，在确认之前会互相交换建立连接所需的信息，其中包含内网 IP。因此，其他地方网段恰好相同的设备（每台最多 8 个）可能看到你的内网 IP，但看不到你的设备，也无法给你发文件。
- 同一房间里的所有设备共享同一个密钥。用完点「退出房间」，下次换一个新配对码。

## 本地运行

```bash
npm install
npm start          # 默认 http://0.0.0.0:3000
```

配对码和局域网直连都需要安全上下文：`localhost` 可以直接用，局域网 IP 访问需要 HTTPS。本机临时测试可用自签名证书：

```bash
mkdir -p certs && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout certs/key.pem -out certs/cert.pem -subj "/CN=drop-anything-local" \
  -addext "subjectAltName=IP:$(ipconfig getifaddr en0),IP:127.0.0.1,DNS:localhost"
HTTPS_PORT=3443 npm start
```

开启中转时（`RELAY=1`），调试可以在网址后加 `?relay`，让本机发出的文件不尝试直连、直接走中转。

## 部署

### Cloudflare Workers（免费，推荐）

`cloudflare/` 目录是配对服务的 Workers 版本，协议与 `server.js` 相同，前端直接复用 `public/`。所有连接由一个 Durable Object 管理，并使用 WebSocket 休眠 API，免费套餐即可运行；自带 `*.workers.dev` 的 HTTPS 域名，不会休眠。

```bash
cd cloudflare
npm install
npx wrangler login    # 在浏览器中登录 Cloudflare 账号并授权
npx wrangler deploy   # 部署完成后会输出 https://drop-anything.<你的子域>.workers.dev
```

本地调试用 `npx wrangler dev`（默认 http://localhost:8787）。Workers 版本默认不允许中转文件（`wrangler.toml` 中 `RELAY = "0"`），开启会消耗请求额度。

### 云服务器

服务器只做配对，最便宜的 VPS 就够用。配上域名和正式 HTTPS 证书后，所有设备打开都不会有证书警告，局域网直连按钮可以直接用。

```bash
git clone <本仓库> && cd drop-anything
npm install --omit=dev
PORT=3000 TRUST_PROXY=1 node server.js
```

长期运行可用 `pm2 start server.js --name drop` 或 systemd。

HTTPS 推荐用 Caddy 自动申请证书，`/etc/caddy/Caddyfile`：

```
drop.example.com {
    reverse_proxy 127.0.0.1:3000
}
```

Caddy 会自动处理 WebSocket。使用反向代理时务必设置 `TRUST_PROXY=1`，否则服务器会把所有人识别成同一个出口 IP。

nginx 需要显式放行 WebSocket：

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 3600s;
}
```

### Docker

```bash
docker build -t drop-anything .
docker run -d -p 3000:3000 -e TRUST_PROXY=1 drop-anything
```

再在前面放一个提供 HTTPS 的反向代理（见上）。

### 树莓派（只在局域网用）

服务器看到的都是内网地址，会把所有客户端视为同一出口，再按各自上报的网段分组。没有域名时，用上面的自签名证书并设置 `HTTPS_PORT`，每台设备第一次打开都要手动信任证书。

### （可选）中转与 TURN

`RELAY=1` 时，直连失败会经服务器 WebSocket 中转，速度取决于服务器带宽。若想让中转也走 UDP，可以在同一台机器装 coturn，并设置：

```bash
TURN_URLS=turn:drop.example.com:3478 TURN_USERNAME=user TURN_CREDENTIAL=pass node server.js
```

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PORT` | `3000` | 监听端口 |
| `HOST` | `0.0.0.0` | 监听地址 |
| `RELAY` | 关闭 | 设为 `1` 时允许经服务器中转文件数据；关闭时服务器丢弃所有中转数据，只转发配对信令 |
| `TRUST_PROXY` | 关闭 | 设为 `1` 时从 `X-Forwarded-For` 读取客户端 IP |
| `HTTPS_PORT` | 不开启 | 额外开一个 HTTPS 端口（证书默认读 `certs/key.pem`、`certs/cert.pem`，可用 `TLS_KEY` / `TLS_CERT` 指定） |
| `STUN_URLS` | Cloudflare + Google | 逗号分隔 |
| `TURN_URLS` / `TURN_USERNAME` / `TURN_CREDENTIAL` | 无 | 可选的 TURN 服务器 |

## 已知限制

- 接收的文件先放在内存里再保存，几 GB 的大文件在手机上可能失败。
- 网段按 /24 或 /16 估算，浏览器拿不到子网掩码。同一出口下、网段相同的两个不同局域网（例如两个默认配置的小米路由器，都是 `192.168.31.x`）会被误认为同一局域网，互相可见但无法直连。
- 同一浏览器同时只有一个标签页在线：在新标签页打开会接管连接，旧标签页显示「已在其他标签页打开」，切回去时再重新接管。
- 开启局域网直连需要摄像头权限；没有摄像头的设备无法开启，只能用配对码让双方互相看到，并由对方开启局域网直连来建立直连。

## 许可证

[MIT](LICENSE)
