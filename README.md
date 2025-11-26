# ech-workers
cloudflare workers proxy

第一步，将workrs.js的代码完整复制粘贴到workers里面\
第二步，启动ech-workers客户端，启动参数-h看帮助文件

Usage:\ 

./ech-workers: \
  -dns string
        ECH 查询 DNS 服务器 (default "119.29.29.29:53")\
  -ech string
        ECH 查询域名 (default "cloudflare-ech.com")\
  -f string
        服务端地址 (格式: x.x.workers.dev:443)\
  -ip string
        指定服务端 IP（绕过 DNS 解析）\
  -l string
        代理监听地址 (支持 SOCKS5 和 HTTP) (default "127.0.0.1:30000")\
  -token string
        身份验证令牌

# ECH-Tunnel-Go  

#### （中转群大神作品，本仓库仅做收藏，有问题去问作者）

单二进制、全平台、纯 Go 实现的多协议加密正向代理

支持 ECH（Encrypted Client Hello） + TLS 1.3 + WebSocket + 多通道竞速 + 完整 SOCKS5/HTTP 代理 + UDP Associate + TCP/UDP 正向转发  
专为极端网络环境设计，一键穿透任何 GFW、运营商、学校、企业级深度包检测。

### 一、特性亮点（真正的杀手锏）

| 特性                         | 是否实现 | 说明                                                                |
|------------------------------|----------|----------------------------------------------------------------------|
| 真实 ECH（非 ESNI）          | Yes      | 强制启用 ECH，拒绝回退，彻底隐藏 SNI                                 |
| ECH 公钥自动获取与轮换       | Yes      | 启动时自动 DNS over UDP 查询 cloudflare-ech.com，支持任意域名         |
| 多通道低延迟竞速             | Yes      | 默认 3 条 WebSocket，最快通道自动获胜（类似 Hysteria2 多路径）       |
| 完整 SOCKS5（含 UDP Associate）| Yes    | 支持用户名密码认证、UDP 全关联，完美兼容 Clash、Surge、Shadowrocket  |
| 完整 HTTP/HTTPS 代理         | Yes      | 支持 CONNECT 隧道、GET/POST 转发，带 Basic 认证                     |
| TCP 正向转发（多规则）       | Yes      | tcp://127.0.0.1:80/8.8.8.8:53 多条规则                           |
| 服务端 IP 白名单（CIDR）     | Yes      | 支持 IPv4/IPv6，精确到单个 IP                                        |
| 零依赖单文件部署             | Yes      | 编译后仅一个可执行文件，无需 Python、Node、Java                     |
| 自签/自定义证书 wss          | Yes      | 支持自签证书自动生成，也可指定 cert+key                              |
| Token + Subprotocol 认证     | Yes      | WebSocket 子协议双重验证，防扫描                                     |
| 完美心跳与自动重连           | Yes      | 10秒 Ping + 30秒超时检测 + 自动重连，永不断线                        |

### 二、使用方式

#### 1. 服务端（VPS 上运行）

# 常用推荐配置
./ech-tunnel -l ws://0.0.0.0:80 -token 你的密码

# 最强推荐配置（自签证书）
./ech-tunnel -l wss://0.0.0.0:443 -token 你的密码

# 使用 Let's Encrypt 证书（推荐）
./ech-tunnel -l wss://0.0.0.0:443 \
            -cert /etc/letsencrypt/live/domain/fullchain.pem \
            -key /etc/letsencrypt/live/domain/privkey.pem \
            -token 你的密码

#### 2. 客户端（电脑/路由器/手机）

# SOCKS5 + HTTP 代理（推荐，功能最全）
./ech-tunnel -l proxy://127.0.0.1:1080 \
            -f wss://你的域名:443 \
            -token 你的密码 \
            -n 4

# TCP 正向转发（透明代理/网关模式）
./ech-tunnel -l tcp://127.0.0.1:80/1.1.1.1:80,127.0.0.1:53/8.8.8.8:53 \
            -f wss://你的域名:443 \
            -token 你的密码 -n 3

# 指定出口 IP（指定 Cloudflare 优选IP）
./ech-tunnel -l proxy://0.0.0.0:1080 \
            -f wss://your.com:443 \
            -ip 104.16.16.16 \
            -token 你的密码 -n 2

### 三、参数说明

| 参数         | 必填 | 说明                                                                 |
|--------------|------|----------------------------------------------------------------------|
| -l         | Yes  | 监听地址（服务端 ws/wss，客户端 tcp/proxy）                           |
| -f         | Yes  | 服务端 wss 地址（客户端必填）                                        |
| -token     | Yes  | WebSocket 子协议密码（建议 6+ 位）                                  |
| -n         | No   | 并发 WebSocket 通道数（推荐 3~8，建议默认）                         |
| -cert/-key | No   | 自定义证书（wss 服务端）                                             |
| -cidr      | No   | 服务端 IP 白名单，默认全部放行                                       |
| -ip        | No   | 客户端指定出口 IP（指定 Cloudflare 优选IP）                            |
| -dns       | No   | 查询 ECH 公钥的 DNS，默认 119.29.29.29:53（腾讯）                       |
| -ech       | No   | ECH 公钥查询域名，默认 cloudflare-ech.com（最稳定）                  |

###四、为什么它能 100% 过检测？

1. **真实 ECH**：SNI 完全加密，连 JA3 指纹都看不到  
2. **多通道竞速**：哪怕有单条通道被限速，其他通道立刻顶上  
3. **10秒心跳 + 2秒自动重连**：网络闪断立即恢复，用户无感知  
4. **纯 TLS 1.3 + 随机化 Padding**：特征与 Chrome 访问 Cloudflare 一模一样  
5. **无回退机制**：一旦 ECH 被拒直接退出，绝不暴露真实 SNI

一个基于 WebSocket 的安全隧道代理工具，支持 TCP 端口转发、SOCKS5 代理和 HTTP 代理，采用 ECH (Encrypted Client Hello) 技术增强隐私保护。

## 功能特性

- **多种代理模式**
  - TCP 端口转发（支持多规则）
  - SOCKS5 代理（支持 TCP CONNECT 和 UDP ASSOCIATE）
  - HTTP/HTTPS 代理（支持 CONNECT 隧道）

- **安全特性**
  - 强制 TLS 1.3 加密传输
  - ECH (Encrypted Client Hello) 支持，隐藏真实 SNI
  - 可选的身份验证令牌
  - 支持用户名密码认证（SOCKS5/HTTP）
  - IP 白名单（CIDR 格式）

- **高性能设计**
  - WebSocket 多路复用
  - 多通道连接池
  - 自动重连机制

## 技术原理

### 整体架构

```
┌──────────────────┐                                    ┌──────────────────┐
│      客户端       │                                    │      服务端       │
│                  │                                    │                  │
│  ┌────────────┐  │      WebSocket (TLS 1.3 + ECH)     │  ┌────────────┐  │
│  │ TCP 转发   │  │◄──────────────────────────────────►│  │ TCP 转发   │  │
│  ├────────────┤  │                                    │  ├────────────┤  │
│  │ SOCKS5    │  │         多路复用 + 连接池            │  │ UDP 转发   │  │
│  ├────────────┤  │                                    │  └────────────┘  │
│  │ HTTP 代理  │  │                                    │                  │
│  └────────────┘  │                                    │                  │
└──────────────────┘                                    └──────────────────┘
```

### ECH (Encrypted Client Hello)

ECH 是 TLS 1.3 的扩展协议，用于加密 ClientHello 消息中的敏感字段，特别是 SNI (Server Name Indication)。

**传统 TLS 握手的问题：**
```
客户端 ──► 明文 SNI: "example.com" ──► 服务器
              ↑
         中间人可见
```

**启用 ECH 后：**
```
客户端 ──► 加密的 SNI ──► 服务器
              ↑
         中间人只能看到外层 SNI (如 cloudflare-ech.com)
```

**ECH 工作流程：**

1. 客户端通过 DNS HTTPS 记录查询目标域名的 ECH 公钥
2. 使用公钥加密真实的 ClientHello（包含真实 SNI）
3. 外层 ClientHello 使用公共的"前端域名"作为 SNI
4. 服务器解密内层 ClientHello，获取真实目标

**本工具的 ECH 实现：**

```
1. 启动时查询 ECH 配置
   ┌─────────┐  DNS HTTPS 查询   ┌─────────┐
   │  客户端  │ ────────────────► │   DNS   │
   │         │ ◄──────────────── │  服务器  │
   └─────────┘   ECH 公钥配置     └─────────┘

2. 建立连接时使用 ECH
   ┌─────────┐  加密的 ClientHello  ┌─────────┐
   │  客户端  │ ──────────────────► │  服务端  │
   │         │    (SNI 被隐藏)      │         │
   └─────────┘                      └─────────┘
```

### WebSocket 多路复用

单个 WebSocket 连接承载多个 TCP/UDP 会话，通过连接 ID 区分：

```
┌─────────────────────────────────────────────────────────┐
│                    WebSocket 连接                        │
├─────────────────────────────────────────────────────────┤
│  [ConnID-1] TCP 会话 1 ◄──► example.com:80              │
│  [ConnID-2] TCP 会话 2 ◄──► example.org:443             │
│  [ConnID-3] UDP 会话 1 ◄──► 8.8.8.8:53                  │
│  ...                                                    │
└─────────────────────────────────────────────────────────┘
```

**消息格式：**

| 类型 | 格式 | 说明 |
|------|------|------|
| TCP 建连 | `TCP:<id>\|<target>\|<data>` | 建立 TCP 连接并发送首帧 |
| 数据传输 | `DATA:<id>\|<payload>` | 双向数据传输 |
| 关闭连接 | `CLOSE:<id>` | 关闭指定会话 |
| UDP 建连 | `UDP_CONNECT:<id>\|<target>` | 建立 UDP 关联 |
| UDP 数据 | `UDP_DATA:<id>\|<data>` | UDP 数据传输 |

### 多通道连接池

客户端维护多个 WebSocket 长连接，通过竞选机制选择最优通道：

```
┌─────────┐
│  客户端  │
└────┬────┘
     │
     ├──► 通道 0 (WebSocket) ──► 服务端
     ├──► 通道 1 (WebSocket) ──► 服务端
     └──► 通道 2 (WebSocket) ──► 服务端

新连接到来时：
1. 向所有通道发送 CLAIM 请求
2. 记录各通道响应时间
3. 选择最先响应的通道处理该连接
```

## 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l` | 监听地址 | 必填 |
| `-f` | WebSocket 服务端地址（客户端模式必填） | - |
| `-ip` | 指定连接的目标 IP 地址 | - |
| `-cert` | TLS 证书文件路径 | 自动生成自签名证书 |
| `-key` | TLS 密钥文件路径 | 自动生成 |
| `-token` | 身份验证令牌 | - |
| `-cidr` | 允许的来源 IP 范围 | `0.0.0.0/0,::/0` |
| `-dns` | ECH 公钥查询 DNS 服务器 | `119.29.29.29:53` |
| `-ech` | ECH 公钥查询域名 | `cloudflare-ech.com` |
| `-n` | WebSocket 连接池大小 | `3` |

## 使用方法

### 服务端

#### 基本启动

```bash
# WSS 服务端（自动生成自签名证书）
ech-tunnel -l wss://0.0.0.0:8443/tunnel

# WS 服务端（不加密，仅测试用）
ech-tunnel -l ws://0.0.0.0:8080/tunnel
```

#### 使用自定义证书

```bash
ech-tunnel -l wss://0.0.0.0:443/tunnel -cert /path/to/cert.pem -key /path/to/key.pem
```

#### 启用身份验证

```bash
ech-tunnel -l wss://0.0.0.0:8443/tunnel -token your-secret-token
```

#### 限制来源 IP

```bash
# 仅允许指定网段
ech-tunnel -l wss://0.0.0.0:8443/tunnel -cidr 192.168.0.0/16,10.0.0.0/8

# 仅允许单个 IP
ech-tunnel -l wss://0.0.0.0:8443/tunnel -cidr 203.0.113.50/32
```

### 客户端

#### SOCKS5/HTTP 代理模式

```bash
# 基本代理
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel

# 带认证的代理
ech-tunnel -l proxy://user:pass@127.0.0.1:1080 -f wss://server.example.com:8443/tunnel

# 使用服务端 token
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -token your-secret-token

# 调整连接池大小
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -n 5
```

#### TCP 端口转发模式

```bash
# 单端口转发
ech-tunnel -l tcp://127.0.0.1:8080/example.com:80 -f wss://server.example.com:8443/tunnel

# 多端口转发
ech-tunnel -l tcp://127.0.0.1:8080/example.com:80,127.0.0.1:8443/example.com:443 -f wss://server.example.com:8443/tunnel

# 内网服务转发
ech-tunnel -l tcp://127.0.0.1:3389/192.168.1.100:3389 -f wss://server.example.com:8443/tunnel
```

#### 指定连接 IP

当需要绕过 DNS 或指定特定 IP 时：

```bash
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -ip 203.0.113.10
```

#### 自定义 ECH 配置

```bash
# 使用其他 DNS 服务器
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -dns 8.8.8.8:53

# 使用其他 ECH 域名
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://server.example.com:8443/tunnel -ech cloudflare.com
```

## 使用场景

### 场景 1：安全代理

**服务端部署在云服务器：**
```bash
ech-tunnel -l wss://0.0.0.0:443/ws -cert cert.pem -key key.pem -token secret123
```

**本地客户端：**
```bash
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://your-server.com/ws -token secret123
```

配置浏览器使用 `127.0.0.1:1080` 作为 SOCKS5 或 HTTP 代理。

### 场景 2：通过 CDN 中转

将服务端域名接入 Cloudflare 等支持 WebSocket 的 CDN：

**服务端：**
```bash
ech-tunnel -l wss://0.0.0.0:443/tunnel -cert cert.pem -key key.pem
```

**客户端：**
```bash
ech-tunnel -l proxy://127.0.0.1:1080 -f wss://your-cdn-domain.com/tunnel
```

### 场景 3：内网穿透

访问内网中的服务：

**服务端（公网）：**
```bash
ech-tunnel -l wss://0.0.0.0:8443/tunnel
```

**客户端：**
```bash
# 将内网 RDP 服务映射到本地
ech-tunnel -l tcp://127.0.0.1:3389/192.168.1.100:3389 -f wss://server.com:8443/tunnel

# 将内网数据库映射到本地
ech-tunnel -l tcp://127.0.0.1:3306/192.168.1.50:3306 -f wss://server.com:8443/tunnel
```

### 场景 4：多服务转发

同时转发多个服务：

```bash
ech-tunnel -l tcp://127.0.0.1:8080/web.internal:80,127.0.0.1:8443/web.internal:443,127.0.0.1:3306/db.internal:3306 -f wss://server.com:8443/tunnel
```

## 代理协议支持

### SOCKS5

完整支持 SOCKS5 协议 (RFC 1928)：

- **认证方式**：无认证 / 用户名密码认证
- **命令支持**：
  - `CONNECT` - TCP 连接
  - `UDP ASSOCIATE` - UDP 转发
- **地址类型**：IPv4 / IPv6 / 域名

### HTTP 代理

- **CONNECT 方法**：用于 HTTPS 隧道
- **普通请求**：GET / POST / PUT / DELETE 等
- **认证**：Basic 认证

## 安全建议

1. **始终使用 WSS** - 生产环境必须使用 `wss://`，避免使用 `ws://`
2. **启用 Token 认证** - 使用 `-token` 设置复杂的认证令牌
3. **限制来源 IP** - 使用 `-cidr` 仅允许可信 IP 连接
4. **使用有效证书** - 生产环境使用 Let's Encrypt 等 CA 签发的证书
5. **定期更换凭据** - 定期更换 token 和代理密码

## 故障排查

### ECH 相关

**问题**：`DNS 查询超时`
```
[客户端] DNS 查询失败: DNS 查询超时，2秒后重试...
```
**解决**：更换 DNS 服务器 `-dns 8.8.8.8:53` 或 `-dns 1.1.1.1:53`

**问题**：`未找到 ECH 参数`
```
[客户端] 未找到 ECH 参数（HTTPS RR key=echconfig/5），2秒后重试...
```
**解决**：更换支持 ECH 的域名 `-ech cloudflare.com`

### 连接相关

**问题**：WebSocket 连接失败
**排查**：
- 确认服务端正在运行
- 检查端口是否开放
- 验证 token 是否匹配
- 检查证书是否有效

**问题**：连接超时
**解决**：增加连接池大小 `-n 5` 或检查网络质量

## 许可证

[MIT](LICENSE)

