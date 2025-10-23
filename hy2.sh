#!/usr/bin/env bash
# 一键安装 Hysteria2 + Clash 可用订阅
set -euo pipefail

# ===== 配置参数（可用环境变量覆盖） =====
HY2_PORT="${HY2_PORT:-8443}"          # Hysteria2 UDP 端口
HY2_PASS="${HY2_PASS:-}"              # Hysteria密码
OBFS_PASS="${OBFS_PASS:-}"            # Salamander混淆密码
NAME_TAG="${NAME_TAG:-MyHysteria}"    # Clash订阅节点名称
SUB_ENABLE="${SUB_ENABLE:-1}"         # 是否启用HTTP订阅服务
SUB_PORT="${SUB_PORT:-8080}"          # HTTP订阅端口
SUB_DIR="${SUB_DIR:-/etc/hysteria}"   # 订阅目录
SUB_PLAIN="${SUB_PLAIN:-subscription.txt}"
SUB_B64="${SUB_B64:-subscription.b64}"
SUB_CLASH="${SUB_CLASH:-subscription_clash.yml}"
# ========================================

# 1) 获取公网IPv4
IPV4="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)"
[ -n "$IPV4" ] || { echo "[ERR] 未检测到公网 IPv4"; exit 1; }
IP_DASH="${IPV4//./-}"
HY2_DOMAIN="${IP_DASH}.sslip.io"
echo "[OK] 使用域名：${HY2_DOMAIN} (A -> ${IPV4})"

# 2) 安装依赖
export DEBIAN_FRONTEND=noninteractive
pkgs=(curl jq openssl python3 ufw)
for b in "${pkgs[@]}"; do
  if ! command -v "$b" >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y "${pkgs[@]}"
    break
  fi
done

# 3) 安装 Hysteria2
if ! command -v hysteria >/dev/null 2>&1; then
  echo "[*] 安装 Hysteria2..."
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) asset="hysteria-linux-amd64";;
    aarch64|arm64) asset="hysteria-linux-arm64";;
    *) asset="hysteria-linux-amd64";;
  esac
  ver="$(curl -fsSL https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name')"
  curl -fL "https://github.com/apernet/hysteria/releases/download/${ver}/${asset}" -o /usr/local/bin/hysteria
  chmod +x /usr/local/bin/hysteria
fi

# 4) 生成随机密码（如果未指定）
[[ -n "$HY2_PASS" ]] || HY2_PASS="$(openssl rand -hex 16)"
[[ -n "$OBFS_PASS" ]] || OBFS_PASS="$(openssl rand -hex 8)"

# 5) 写 Hysteria2 配置
install -d -m 755 /etc/hysteria
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

# 6) systemd服务
cat >/etc/systemd/system/hysteria-server.service <<'SVC'
[Unit]
Description=Hysteria Server
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

# 7) 防火墙 UFW
if command -v ufw >/dev/null 2>&1; then
  sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw || true
  ufw allow 22
  ufw allow ${HY2_PORT}/udp || true
  ufw allow 80/tcp || true
  [ "${SUB_ENABLE}" = "1" ] && ufw allow ${SUB_PORT}/tcp || true
  yes | ufw enable >/dev/null 2>&1 || true
fi

# 8) 启动 Hysteria2
systemctl daemon-reload
systemctl enable --now hysteria-server
sleep 1
echo "[OK] Hysteria2 已启动，监听 UDP/${HY2_PORT}"

# 9) 构造节点URI
enc() { python3 - <<'PY' "$1"
import sys, urllib.parse as u
print(u.quote(sys.argv[1], safe=''))
PY
}
PASS_ENC="$(enc "$HY2_PASS")"
OBFS_ENC="$(enc "$OBFS_PASS")"
NAME_ENC="$(enc "$NAME_TAG")"
URI="hysteria2://${PASS_ENC}@${HY2_DOMAIN}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0#${NAME_ENC}"

# 10) 生成订阅文件
install -d -m 755 "${SUB_DIR}"
echo "${URI}" > "${SUB_DIR}/${SUB_PLAIN}"
if base64 --help >/dev/null 2>&1 && base64 -w 0 </dev/null >/dev/null 2>&1; then
  base64 -w 0 "${SUB_DIR}/${SUB_PLAIN}" > "${SUB_DIR}/${SUB_B64}"
else
  python3 - <<PY > "${SUB_DIR}/${SUB_B64}"
import base64,sys
print(base64.b64encode(open(sys.argv[1],'rb').read()).decode('ascii'), end='')
PY
fi

cat >"${SUB_DIR}/${SUB_CLASH}" <<EOF
proxies:
  - name: "${NAME_TAG}"
    type: hysteria
    server: "${HY2_DOMAIN}"
    port: ${HY2_PORT}
    password: "${HY2_PASS}"
    obfs: "salamander"
    obfs-password: "${OBFS_PASS}"
    protocol: "udp"
    sni: "${HY2_DOMAIN}"
    skip-cert-verify: false
    udp: true

proxy-groups:
  - name: "Auto"
    type: select
    proxies:
      - "${NAME_TAG}"

proxy-providers: {}
EOF

# 11) 可选 HTTP 服务
if [ "${SUB_ENABLE}" = "1" ]; then
  cat >/etc/systemd/system/hysteria-sub.service <<SVC
[Unit]
Description=Hysteria HTTP subscription
After=network.target

[Service]
User=root
ExecStart=/usr/bin/python3 -m http.server ${SUB_PORT} --directory ${SUB_DIR} --bind 0.0.0.0
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SVC
  systemctl daemon-reload
  systemctl enable --now hysteria-sub.service || true
fi

# 12) 输出订阅信息
echo
echo "Clash YAML订阅：http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_CLASH}"
echo "单行 URI：http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_PLAIN}"
echo "Base64：http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_B64}"
echo
echo "提示：首次与续期均需 80/tcp 外网可达（HTTP-01）。"
