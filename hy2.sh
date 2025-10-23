#!/usr/bin/env bash
set -euo pipefail

# ===== 可改参数 =====
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

# 0) 公网 IPv4
IPV4="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
[ -n "$IPV4" ] || { echo "[ERR] 未检测到公网 IPv4"; exit 1; }

# 生成零配置域名
IP_DASH="${IPV4//./-}"
HY2_DOMAIN="${IP_DASH}.sslip.io"
RES_A="$(getent ahostsv4 "$HY2_DOMAIN" | awk '{print $1}' | head -n1 || true)"
if [ "$RES_A" != "$IPV4" ] || [ -z "$RES_A" ]; then
  ALT="${IP_DASH}.nip.io"
  RES2="$(getent ahostsv4 "$ALT" | awk '{print $1}' | head -n1 || true)"
  if [ "$RES2" = "$IPV4" ]; then
    HY2_DOMAIN="$ALT"
  else
    echo "[ERR] sslip.io / nip.io 无法解析到本机 IP"
    exit 1
  fi
fi
echo "[OK] 使用域名：${HY2_DOMAIN} (A -> ${IPV4})"

# 生成密码
[[ -n "$HY2_PASS"  ]] || HY2_PASS="$(openssl rand -hex 16)"
[[ -n "$OBFS_PASS" ]] || OBFS_PASS="$(openssl rand -hex 8)"

# 输出节点（hysteria2 URI）
enc() { python3 - <<'PY' "$1"
import sys, urllib.parse as u
print(u.quote(sys.argv[1], safe=''))
PY
}
PASS_ENC="$(enc "$HY2_PASS")"
OBFS_ENC="$(enc "$OBFS_PASS")"
NAME_ENC="$(enc "$NAME_TAG")"
PIN_ENC="$(enc "$PIN_SHA256")"

URI="hysteria2://${PASS_ENC}@${HY2_DOMAIN}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"

echo
echo "=========== HY2 节点 ==========="
echo "${URI}"
echo "================================"

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

# Clash YAML（精简兼容）
CLASH_PATH="${SUB_DIR}/${SUB_CLASH}"
cat >"${CLASH_PATH}" <<EOF
# Auto-generated Clash subscription (single hysteria node)
proxies:
  - name: "${NAME_TAG}"
    type: hysteria
    server: "${HY2_DOMAIN}"
    port: ${HY2_PORT}
    password: "${HY2_PASS}"
    obfs: "${OBFS_PASS}"
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
chmod 644 "${CLASH_PATH}"

# 可选 HTTP 订阅服务
if [ "${SUB_ENABLE}" = "1" ]; then
  cat >/etc/systemd/system/hysteria-sub.service <<SVC
[Unit]
Description=Simple HTTP server for Hysteria subscription
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
  echo "Base64：http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_B64}"
fi
