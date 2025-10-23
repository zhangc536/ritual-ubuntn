#!/usr/bin/env bash
set -euo pipefail

# ===== 可改参数 =====
HY2_PORT="${HY2_PORT:-8443}"          # Hysteria2 UDP端口
HY2_PASS="${HY2_PASS:-}"              # HY2 密码（留空自动生成）
OBFS_PASS="${OBFS_PASS:-}"            # 混淆密码（留空自动生成）
NAME_TAG="${NAME_TAG:-MyHysteria}"    # 节点名称
PIN_SHA256="${PIN_SHA256:-}"          # 证书指纹（可留空）

CLASH_WEB_DIR="${CLASH_WEB_DIR:-/etc/hysteria}"
CLASH_OUT_PATH="${CLASH_OUT_PATH:-${CLASH_WEB_DIR}/clash_subscription.yaml}"
HTTP_PORT="${HTTP_PORT:-8080}"

# ===========================
# 0) 获取公网 IPv4
# ===========================
SELECTED_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
if [ -z "${SELECTED_IP}" ]; then
  echo "[ERR] 未检测到公网 IPv4，脚本退出"
  exit 1
fi
echo "[OK] 使用 IP: ${SELECTED_IP}"

# ===========================
# 1) 安装依赖
# ===========================
export DEBIAN_FRONTEND=noninteractive
pkgs=(curl jq openssl python3 nginx)
MISSING=0
for p in "${pkgs[@]}"; do
  if ! command -v "$p" >/dev/null 2>&1; then
    MISSING=1
    break
  fi
done
if [ "$MISSING" -eq 1 ]; then
  apt-get update -y
  apt-get install -y "${pkgs[@]}"
fi

# ===========================
# 2) 生成域名（sslip.io 优先 -> nip.io -> FAIL）
# ===========================
IP_DASH="${SELECTED_IP//./-}"
HY2_DOMAIN="${IP_DASH}.sslip.io"

RES_A="$(getent ahostsv4 "$HY2_DOMAIN" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
if [ -z "$RES_A" ] || [ "$RES_A" != "$SELECTED_IP" ]; then
  ALT="${IP_DASH}.nip.io"
  RES2="$(getent ahostsv4 "$ALT" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
  if [ -n "$RES2" ] && [ "$RES2" = "$SELECTED_IP" ]; then
    HY2_DOMAIN="$ALT"
  else
    echo "[ERR] sslip.io / nip.io 均未解析到本机 IP（${SELECTED_IP}）。"
    echo "       ACME HTTP-01 需要域名解析到本机并保证 80/tcp 可达。"
    echo "       请在 DNS 或环境调整后重试。脚本退出。"
    exit 1
  fi
fi
echo "[OK] 使用域名：${HY2_DOMAIN} -> ${SELECTED_IP}"

# ===========================
# 3) 安装 hysteria 二进制（若不存在）
# ===========================
if ! command -v hysteria >/dev/null 2>&1; then
  echo "[*] 安装 hysteria ..."
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) asset="hysteria-linux-amd64" ;;
    aarch64|arm64) asset="hysteria-linux-arm64" ;;
    *) asset="hysteria-linux-amd64" ;;
  esac
  ver="$(curl -fsSL https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name')"
  curl -fL "https://github.com/apernet/hysteria/releases/download/${ver}/${asset}" -o /usr/local/bin/hysteria
  chmod +x /usr/local/bin/hysteria
fi

# ===========================
# 4) 生成密码（若未提供）
# ===========================
if [ -z "${HY2_PASS}" ]; then
  HY2_PASS="$(openssl rand -hex 16)"
fi
if [ -z "${OBFS_PASS}" ]; then
  OBFS_PASS="$(openssl rand -hex 8)"
fi

# ===========================
# 5) 写 Hysteria2 配置（ACME HTTP-01）
# ===========================
mkdir -p /etc/hysteria
cat >/etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}

auth:
  type: password
  password: ${HY2_PASS}

obfs:
  type: salamander
  salamander:
    password: ${OBFS_PASS}

acme:
  domains:
    - ${HY2_DOMAIN}
  disable_http_challenge: false
  disable_tlsalpn_challenge: true
EOF

# ===========================
# 6) systemd 服务： hysteria-server
# ===========================
cat >/etc/systemd/system/hysteria-server.service <<'SVC'
[Unit]
Description=Hysteria Server (config.yaml)
After=network.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable --now hysteria-server
sleep 3

# ===========================
# 7) 等待并检查 ACME 证书是否完成
# ===========================
echo "[*] 等待 hysteria 完成 ACME HTTP-01 验证（最多 60 秒）..."
TRIES=0
ACME_OK=0
while [ $TRIES -lt 12 ]; do
  # 检查 systemd 日志里是否出现 acme 相关成功信息
  if journalctl -u hysteria-server --no-pager -n 200 | grep -iq "acme"; then
    ACME_OK=1
    break
  fi
  sleep 5
  TRIES=$((TRIES+1))
done

if [ "$ACME_OK" -ne 1 ]; then
  echo "[ERR] ACME HTTP-01 证书申请未检测到成功记录。请确认 ${HY2_DOMAIN} 解析正确且 80/tcp 可达。"
  echo "      hysteria 日志预览："
  journalctl -u hysteria-server -n 100 --no-pager || true
  exit 1
fi
echo "[OK] ACME 证书（或相关 acme 日志）已检测到"

echo "=== 监听检查（UDP/${HY2_PORT}) ==="
ss -lunp | grep -E ":${HY2_PORT}\b" || true

# ===========================
# 8) 构造 hysteria2 URI（URL 编码关键字段）
# ===========================
PASS_ENC="$(python3 - <<PY
import sys, urllib.parse as u
print(u.quote(sys.argv[1], safe=''))
PY
" "$HY2_PASS")"

OBFS_ENC="$(python3 - <<PY
import sys, urllib.parse as u
print(u.quote(sys.argv[1], safe=''))
PY
" "$OBFS_PASS")"

NAME_ENC="$(python3 - <<PY
import sys, urllib.parse as u
print(u.quote(sys.argv[1], safe=''))
PY
" "$NAME_TAG")"

PIN_ENC="$(python3 - <<PY
import sys, urllib.parse as u
print(u.quote(sys.argv[1], safe=''))
PY
" "$PIN_SHA256")"

URI="hysteria2://${PASS_ENC}@${SELECTED_IP}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"

echo
echo "=========== HY2 节点（URI） ==========="
echo "${URI}"
echo "======================================="
echo

# ===========================
# 9) 生成规则模式友好 的 Clash 订阅（包含 proxy-groups、dns、rules）
# ===========================
mkdir -p "${CLASH_WEB_DIR}"
cat > "${CLASH_OUT_PATH}" <<EOF
# Auto-generated Clash subscription (rules-mode friendly)
proxies:
  - type: hysteria2
    name: ${NAME_TAG}
    server: ${SELECTED_IP}
    port: ${HY2_PORT}
    password: ${HY2_PASS}
    obfs: salamander
    obfs-password: ${OBFS_PASS}
    sni: ${HY2_DOMAIN}

proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - ${NAME_TAG}
      - DIRECT

  - name: Auto
    type: url-test
    url: 'http://www.gstatic.com/generate_204'
    interval: 300
    proxies:
      - ${NAME_TAG}
      - DIRECT

dns:
  enable: true
  listen: 0.0.0.0:53
  enhanced-mode: fake-ip
  default-nameserver:
    - 223.5.5.5
    - 1.1.1.1
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.4.4/dns-query
  fallback:
    - https://dns.google/dns-query
    - https://1.0.0.1/dns-query
  use-hosts: true

rules:
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
EOF

echo "[OK] Clash 订阅已写入：${CLASH_OUT_PATH}"

# ===========================
# 10) 配置 nginx 提供订阅
# ===========================
cat >/etc/nginx/sites-available/clash.conf <<EOF
server {
    listen ${HTTP_PORT} default_server;
    listen [::]:${HTTP_PORT} default_server;

    root ${CLASH_WEB_DIR};

    location /clash_subscription.yaml {
        default_type application/x-yaml;
        try_files /clash_subscription.yaml =404;
    }

    access_log /var/log/nginx/clash_access.log;
    error_log /var/log/nginx/clash_error.log;
}
EOF

ln -sf /etc/nginx/sites-available/clash.conf /etc/nginx/sites-enabled/clash.conf
nginx -t
systemctl restart nginx

echo "[OK] Clash 订阅通过 nginx 提供："
echo "    http://${SELECTED_IP}:${HTTP_PORT}/clash_subscription.yaml"
echo
echo "提示：首次或续期 ACME 证书仍需 80/tcp 外网可达"
