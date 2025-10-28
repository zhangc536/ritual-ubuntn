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

# ---- helper: escape replacement for sed (escape & and / and @ and newline) ----
escape_for_sed() {
  # read input as $1
  printf '%s' "$1" | sed -e 's/[\/&@]/\\&/g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
}

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
# 1) 安装依赖（如缺失）
# ===========================
export DEBIAN_FRONTEND=noninteractive
pkgs=(curl jq openssl python3 nginx)
MISSING=0
for p in "${pkgs[@]}"; do
  if ! command -v "$p" >/dev/null 2>&1; then MISSING=1; break; fi
done
if [ "$MISSING" -eq 1 ]; then
  apt-get update -y
  apt-get install -y "${pkgs[@]}"
fi

# ===========================
# 2) 生成域名（sslip.io 优先 -> nip.io -> warn）
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
    echo "[WARN] sslip.io / nip.io 未解析到该 IP（${SELECTED_IP}）。"
    echo "       若要使用 ACME HTTP-01，请确保域名解析到本机且 80/tcp 可达。"
  fi
fi
echo "[OK] 使用域名/IP：${HY2_DOMAIN} -> ${SELECTED_IP}"

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
# 4) 密码生成（若未提供）
# ===========================
if [ -z "${HY2_PASS}" ]; then
  HY2_PASS="$(openssl rand -hex 16)"
fi
if [ -z "${OBFS_PASS}" ]; then
  OBFS_PASS="$(openssl rand -hex 8)"
fi

# ===========================
# 5) 在 /acme 下扫描子目录寻找 fullchain.pem + privkey.pem（优先使用）
# ===========================
USE_EXISTING_CERT=0
USE_CERT_PATH=""
USE_KEY_PATH=""
ACME_BASE="/acme"

if [ -d "$ACME_BASE" ]; then
  while IFS= read -r -d '' cert_dir; do
    FULLCHAIN="${cert_dir}/fullchain.pem"
    PRIVKEY="${cert_dir}/privkey.pem"
    if [ -f "$FULLCHAIN" ] && [ -f "$PRIVKEY" ]; then
      USE_EXISTING_CERT=1
      USE_CERT_PATH="$FULLCHAIN"
      USE_KEY_PATH="$PRIVKEY"
      echo "[OK] 检测到证书：$FULLCHAIN"
      break
    fi
  done < <(find "$ACME_BASE" -type d -print0)
fi

if [ "$USE_EXISTING_CERT" -eq 0 ]; then
  echo "[INFO] /acme 下未找到证书，脚本将尝试 ACME HTTP-01（需 80/tcp 可达）"
fi

# ===========================
# 6) 写 hysteria 配置（使用已找到的证书或 ACME 配置）
# ===========================
mkdir -p /etc/hysteria
if [ "$USE_EXISTING_CERT" -eq 1 ]; then
  cat >/etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}

auth:
  type: password
  password: ${HY2_PASS}

obfs:
  type: salamander
  salamander:
    password: ${OBFS_PASS}

tls:
  cert: ${USE_CERT_PATH}
  key: ${USE_KEY_PATH}
EOF
  echo "[OK] 已写入 hysteria 配置（使用 /acme 证书）"
else
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
  echo "[OK] 已写入 hysteria 配置（使用 ACME HTTP-01）"
fi

# ===========================
# 7) systemd 服务 hysteria-server
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
# 8) 如果没有现有证书则等待 ACME 产生日志（最多 60 秒）
# ===========================
if [ "$USE_EXISTING_CERT" -eq 0 ]; then
  echo "[*] 等待 hysteria ACME 证书申请完成（最多 60 秒）..."
  TRIES=0
  ACME_OK=0
  while [ $TRIES -lt 12 ]; do
    if journalctl -u hysteria-server --no-pager -n 200 | grep -E -iq "(certificate obtained successfully|acme_client.*authorization finalized|acme.*valid)"; then
      ACME_OK=1
      break
    fi
    sleep 5
    TRIES=$((TRIES+1))
  done

  if [ "$ACME_OK" -ne 1 ]; then
    echo "[WARN] 未检测到 ACME 成功日志，但可能证书已申请成功。检查日志详情："
    journalctl -u hysteria-server -n 50 --no-pager | grep -E -i "(acme|certificate|tls-alpn|http-01|challenge)" || true
    echo "[INFO] 继续执行，证书可能已成功获取"
  else
    echo "[OK] ACME 证书申请成功检测到"
  fi
else
  echo "[OK] 使用现有 /acme 证书，跳过 ACME 等待"
fi

echo "=== 监听检查（UDP/${HY2_PORT}) ==="
ss -lunp | grep -E ":${HY2_PORT}\b" || true

# ===========================
# 9) 构造 hysteria2 URI（URLEncode 关键字段，并处理空 pin）
# ===========================
# 确保 PIN_SHA256 非空（若空则用空字符串）
if [ -z "${PIN_SHA256:-}" ]; then
  PIN_SHA256=""
fi

PASS_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$HY2_PASS")"
OBFS_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$OBFS_PASS")"
NAME_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$NAME_TAG")"
PIN_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$PIN_SHA256")"

URI="hysteria2://${PASS_ENC}@${SELECTED_IP}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"

echo
echo "=========== HY2 节点（URI） ==========="
echo "${URI}"
echo "======================================="
echo

# ===========================
# 10) 生成 ACL4SSR 规则的 Clash 订阅（模板写入 + 安全替换）
# ===========================
mkdir -p "${CLASH_WEB_DIR}"

cat > "${CLASH_OUT_PATH}.tmp" <<'EOF'
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

dns:
  enable: true
  listen: 0.0.0.0:53
  default-nameserver:
    - 223.5.5.5
    - 8.8.8.8
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query

proxies:
  - name: "__NAME_TAG__"
    type: hysteria2
    server: __SELECTED_IP__
    port: __HY2_PORT__
    password: __HY2_PASS__
    obfs: salamander
    obfs-password: __OBFS_PASS__
    sni: __HY2_DOMAIN__

proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies:
      - "__NAME_TAG__"
      - DIRECT

rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - DOMAIN-KEYWORD,baidu,DIRECT
  - DOMAIN-KEYWORD,taobao,DIRECT
  - DOMAIN-KEYWORD,qq,DIRECT
  - DOMAIN-KEYWORD,weixin,DIRECT
  - DOMAIN-KEYWORD,alipay,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🚀 节点选择
EOF

# perform safe substitutions
TMPF="${CLASH_OUT_PATH}.tmp"
TARGET="${CLASH_OUT_PATH}"

NAME_ESC="$(escape_for_sed "${NAME_TAG}")"
IP_ESC="$(escape_for_sed "${SELECTED_IP}")"
PORT_ESC="$(escape_for_sed "${HY2_PORT}")"
PASS_ESC="$(escape_for_sed "${HY2_PASS}")"
OBFS_ESC="$(escape_for_sed "${OBFS_PASS}")"
DOMAIN_ESC="$(escape_for_sed "${HY2_DOMAIN}")"

sed -e "s@__NAME_TAG__@${NAME_ESC}@g" \
    -e "s@__SELECTED_IP__@${IP_ESC}@g" \
    -e "s@__HY2_PORT__@${PORT_ESC}@g" \
    -e "s@__HY2_PASS__@${PASS_ESC}@g" \
    -e "s@__OBFS_PASS__@${OBFS_ESC}@g" \
    -e "s@__HY2_DOMAIN__@${DOMAIN_ESC}@g" \
    "${TMPF}" > "${TARGET}"
rm -f "${TMPF}"

echo "[OK] Clash 订阅已写入：${TARGET}"

# ===========================
# 11) 配置 nginx 提供订阅
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
echo "提示：导入订阅后，在 Clash 客户端将 Proxy 组或 Stream/Game/VoIP 组指向你的节点并测试。"
