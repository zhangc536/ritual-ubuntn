#!/usr/bin/env bash
# HY2 (Hysteria2) on IPv4-only VPS WITHOUT own domain & WITHOUT email
# Prints hysteria2:// node and generates Clash YAML compatible with latest Clash.

set -euo pipefail

HY2_PORT="${HY2_PORT:-8443}"
HY2_PASS="${HY2_PASS:-}"
OBFS_PASS="${OBFS_PASS:-}"
NAME_TAG="${NAME_TAG:-MyHysteria}"
PIN_SHA256="${PIN_SHA256:-}"

SUB_ENABLE="${SUB_ENABLE:-1}"
SUB_PORT="${SUB_PORT:-8080}"
SUB_DIR="${SUB_DIR:-/etc/hysteria}"
SUB_PLAIN="${SUB_PLAIN:-subscription.txt}"
SUB_B64="${SUB_B64:-subscription.b64}"
SUB_CLASH="${SUB_CLASH:-subscription_clash.yml}"

IPV4="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
[ -n "$IPV4" ] || { echo "[ERR] 未检测到公网 IPv4"; exit 1; }

# 安装依赖
export DEBIAN_FRONTEND=noninteractive
pkgs=(curl jq openssl ufw python3)
for b in "${pkgs[@]}"; do
  if ! command -v "$b" >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y "${pkgs[@]}"
    break
  fi
done

# 域名生成
IP_DASH="${IPV4//./-}"
HY2_DOMAIN="${IP_DASH}.sslip.io"
RES_A="$(getent ahostsv4 "$HY2_DOMAIN" | awk '{print $1}' | head -n1 || true)"
if [ "$RES_A" != "$IPV4" ] || [ -z "$RES_A" ]; then
  ALT="${IP_DASH}.nip.io"
  RES2="$(getent ahostsv4 "$ALT" | awk '{print $1}' | head -n1 || true)"
  if [ "$RES2" = "$IPV4" ]; then
    HY2_DOMAIN="$ALT"
  else
    echo "[ERR] sslip.io / nip.io 无法解析到本机 IP；请检查 DNS/网络"
    exit 1
  fi
fi
echo "[OK] 使用域名：${HY2_DOMAIN} (A -> ${IPV4})"

# 检查 80 端口
if ss -ltn '( sport = :80 )' | grep -q ':80'; then
  echo "[ERR] 80/tcp 已被占用"
  exit 1
fi

# 安装 Hysteria2
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

# 生成密码
[[ -n "$HY2_PASS" ]] || HY2_PASS="$(openssl rand -hex 16)"
[[ -n "$OBFS_PASS" ]] || OBFS_PASS="$(openssl rand -hex 8)"

# HY2 配置
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

# systemd 服务
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

# 防火墙
if command -v ufw >/dev/null 2>&1; then
  sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw || true
  ufw allow 22
  ufw allow ${HY2_PORT}/udp || true
  ufw allow 80/tcp || true
  [ "${SUB_ENABLE}" = "1" ] && ufw allow ${SUB_PORT}/tcp || true
  yes | ufw enable >/dev/null 2>&1 || true
fi

systemctl daemon-reload
systemctl enable --now hysteria-server
sleep 1

# URL 编码函数
enc() { python3 - <<'PY' "$1"
import sys, urllib.parse as u
print(u.quote(sys.argv[1], safe=''))
PY
}

PASS_ENC="$(enc "$HY2_PASS")"
OBFS_ENC="$(enc "$OBFS_PASS")"
NAME_ENC="$(enc "$NAME_TAG")"
PIN_ENC="$(enc "$PIN_SHA256")"

# 节点 URI
URI="hysteria2://${PASS_ENC}@${HY2_DOMAIN}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"

echo
echo "=========== HY2 节点 ==========="
echo "${URI}"
echo "==============================="

# 生成订阅文件
install -d -m 755 "${SUB_DIR}"
printf '%s\n' "${URI}" > "${SUB_DIR}/${SUB_PLAIN}"
chmod 644 "${SUB_DIR}/${SUB_PLAIN}"

# Base64
if base64 --help >/dev/null 2>&1 && base64 -w 0 </dev/null >/dev/null 2>&1; then
  base64 -w 0 "${SUB_DIR}/${SUB_PLAIN}" > "${SUB_DIR}/${SUB_B64}"
else
  python3 - <<PY > "${SUB_DIR}/${SUB_B64}"
import base64,sys
print(base64.b64encode(open(sys.argv[1],'rb').read()).decode('ascii'), end='')
PY
fi
chmod 644 "${SUB_DIR}/${SUB_B64}"

# Clash YAML 兼容最新版本
CLASH_PATH="${SUB_DIR}/${SUB_CLASH}"
cat >"${CLASH_PATH}" <<EOF
# Auto-generated Clash subscription (single hysteria node)
proxies:
  - name: "${NAME_TAG}"
    type: hysteria
    server: "${HY2_DOMAIN}"
    port: ${HY2_PORT}
    password: "${HY2_PASS}"
    obfs: salamander
    protocol: udp
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
chmod 644 "${CLASH_PATH}"

# 可选 HTTP 订阅服务
if [ "${SUB_ENABLE}" = "1" ]; then
  cat >/etc/systemd/system/hysteria-sub.service <<SVC
[Unit]
Description=HTTP server for Hysteria subscription
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

echo
if [ "${SUB_ENABLE}" = "1" ]; then
  echo "Clash YAML 订阅：http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_CLASH}"
  echo "单行 URI：http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_PLAIN}"
  echo "Base64：  http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_B64}"
fi
echo "提示：首次与续期均需 80/tcp 外网可达（HTTP-01）。"
