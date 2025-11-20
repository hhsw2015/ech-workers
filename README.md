# ech-workers
cloudflare workers proxy

第一步，将workrs.txt的代码完整复制粘贴到workers里面\
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

Bash

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

Bash

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
