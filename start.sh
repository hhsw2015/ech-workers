#!/bin/bash
set -e

curl -L -f --retry 3 \
  https://github.com/cloudflare/cloudflared/releases/download/2025.11.1/cloudflared-linux-amd64 \
  -o cloudflared && chmod +x cloudflared

curl -L -f --retry 3 \
  https://github.com/hhsw2015/ech-workers/raw/refs/heads/main/ech-tunnel-linux-amd64 \
  -o ech-tunnel && chmod +x ech-tunnel

# ======== 请在这里修改你的配置 ========
#CLOUDFLARE_URL="ech-img.playingapi.tech" # 你的 cloudflared 域名
CLOUDFLARE_TOKEN="eyJhIjoiODllMDYzZWYxOGQ3ZmVjZjhlY2E2NTBiYWFjNzZjYmYiLCJ0IjoiZDg4ZjU5OTctZGE3Mi00MzNmLWE5NGUtNGY5MjcyOWU3NTYwIiwicyI6Ik1UZ3dZalU0T1RVdE5qVTJOQzAwTmpJeExXSTJaak10TVRnNU5UazRaVEZqTVRJMCJ9"
ECH_TUNNEL_TOKEN="7bd57098-82bd-4dfa-b32c-9943a52d354f" # ech-tunnel 共享 token
#LOCAL_ADDR="127.0.0.1:8888"                             # ech-tunnel 监听地址

echo "启动 ech-tunnel 服务端（监听 8888）..."
./ech-tunnel -l ws://127.0.0.1:8888 -token $ECH_TUNNEL_TOKEN >ech.log 2>&1 &

sleep 3

echo "启动 cloudflared ..."
./cloudflared tunnel run --no-tls-verify --token $CLOUDFLARE_TOKEN >cf.log 2>&1 &

echo "============================================"
echo "部署成功！你的专属 ECH 节点已上线"
echo ""
echo "============================================"

tail -f ech.log cf.log
