#!/usr/bin/env bash
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
# 0) 公网 IPv4
# ===========================
SELECTED_IP="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
[ -n "$SELECTED_IP" ] || { echo "[ERR] 未检测到公网 IPv4"; exit 1; }
echo "[OK] 使用 IP: ${SELECTED_IP}"

# ===========================
# 1) 安装依赖
# ===========================
export DEBIAN_FRONTEND=noninteractive
pkgs=(curl jq openssl python3 nginx)
for b in "${pkgs[@]}"; do
    if ! command -v "$b" >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y "${pkgs[@]}"
        break
    fi
done

# ===========================
# 2) 自动生成域名（sslip.io 优先）
# ===========================
IP_DASH="${SELECTED_IP//./-}"
HY2_DOMAIN="${IP_DASH}.sslip.io"
RES_A="$(getent ahostsv4 "$HY2_DOMAIN" | awk '{print $1}' | head -n1 || true)"
if [ "$RES_A" != "$SELECTED_IP" ] || [ -z "$RES_A" ]; then
    ALT="${IP_DASH}.nip.io"
    RES2="$(getent ahostsv4 "$ALT" | awk '{print $1}' | head -n1 || true)"
    if [ "$RES2" = "$SELECTED_IP" ]; then
        HY2_DOMAIN="$ALT"
    else
        echo "[WARN] sslip.io / nip.io 未解析到该 IP，请确保 ACME 80/tcp 可达"
        HY2_DOMAIN="$SELECTED_IP"
    fi
fi
echo "[OK] 使用域名/IP：${HY2_DOMAIN} (实际 IP -> ${SELECTED_IP})"

# ===========================
# 3) 安装 Hysteria2
# ===========================
if ! command -v hysteria >/dev/null 2>&1; then
    echo "[*] 安装 Hysteria2 ..."
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
# 4) 密码生成
# ===========================
[[ -n "$HY2_PASS" ]] || HY2_PASS="$(openssl rand -hex 16)"
[[ -n "$OBFS_PASS" ]] || OBFS_PASS="$(openssl rand -hex 8)"

# ===========================
# 5) 写 Hysteria2 配置
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
# 6) systemd 服务
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
sleep 2

# ===========================
# 7) ACME 检查
# ===========================
ACME_OK=true
systemctl status hysteria-server | grep -iq "acme" || ACME_OK=false
if ! $ACME_OK ; then
    echo "[ERR] ACME HTTP-01 证书申请失败，请确保 80/tcp 外网可达"
    exit 1
fi
echo "[OK] ACME 证书申请成功"

# ===========================
# 8) 节点 URL
# ===========================
PASS_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$HY2_PASS''', safe=''))")
OBFS_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$OBFS_PASS''', safe=''))")
NAME_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$NAME_TAG''', safe=''))")
PIN_ENC=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PIN_SHA256''', safe=''))")

URI="hysteria2://${PASS_ENC}@${SELECTED_IP}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"

echo
echo "=========== HY2 节点 ==========="
echo "${URI}"
echo "================================"
echo

# ===========================
# 9) 生成 Clash YAML
# ===========================
mkdir -p "$CLASH_WEB_DIR"
cat > "$CLASH_OUT_PATH" <<EOF
proxies:
  - type: hysteria2
    name: ${NAME_TAG}
    server: ${SELECTED_IP}
    port: ${HY2_PORT}
    password: ${HY2_PASS}
    obfs: salamander
    obfs-password: ${OBFS_PASS}
    sni: ${HY2_DOMAIN}
EOF

# ===========================
# 10) nginx 提供订阅
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

echo "[OK] Clash 订阅已生成并可通过 nginx 访问："
echo "    http://${SELECTED_IP}:${HTTP_PORT}/clash_subscription.yaml"
echo
echo "提示：首次或续期 ACME 证书仍需 80/tcp 外网可达"

