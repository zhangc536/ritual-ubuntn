#!/usr/bin/env bash
set -euo pipefail

# ===== 可改参数 =====
HY2_PORT="${HY2_PORT:-8443}"          # HY2 监听端口
HY2_PASS="${HY2_PASS:-}"              # Hysteria 密码
OBFS_PASS="${OBFS_PASS:-}"            # Salamander 混淆密码
NAME_TAG="${NAME_TAG:-MyHysteria}"    # Clash 名称
SUB_ENABLE="${SUB_ENABLE:-1}"         # 是否启用 HTTP 订阅
SUB_PORT="${SUB_PORT:-8080}"          # HTTP 订阅端口
SUB_DIR="${SUB_DIR:-/etc/hysteria}"   # 订阅目录
SUB_CLASH="${SUB_CLASH:-subscription_clash.yml}"
SUB_PLAIN="${SUB_PLAIN:-subscription.txt}"
SUB_B64="${SUB_B64:-subscription.b64}"
# =====================

# 1) 获取公网 IPv4
IPV4="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1)"
[ -n "$IPV4" ] || { echo "[ERR] 未检测到公网 IPv4"; exit 1; }
IP_DASH="${IPV4//./-}"
HY2_DOMAIN="${IP_DASH}.sslip.io"

# 2) 生成随机密码（如果未指定）
[[ -n "$HY2_PASS"  ]] || HY2_PASS="$(openssl rand -hex 16)"
[[ -n "$OBFS_PASS" ]] || OBFS_PASS="$(openssl rand -hex 8)"

# 3) 写 config.yaml（可直接用）
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

# 4) 构造 URI（Clash 可用单行）
enc() { python3 - <<'PY' "$1"
import sys, urllib.parse as u
print(u.quote(sys.argv[1], safe=''))
PY
}
PASS_ENC="$(enc "$HY2_PASS")"
OBFS_ENC="$(enc "$OBFS_PASS")"
NAME_ENC="$(enc "$NAME_TAG")"

URI="hysteria2://${PASS_ENC}@${HY2_DOMAIN}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0#${NAME_ENC}"

# 5) 生成订阅文件
install -d -m 755 "${SUB_DIR}"
echo "${URI}" > "${SUB_DIR}/${SUB_PLAIN}"

# Base64 单行
if base64 --help >/dev/null 2>&1 && base64 -w 0 </dev/null >/dev/null 2>&1; then
  base64 -w 0 "${SUB_DIR}/${SUB_PLAIN}" > "${SUB_DIR}/${SUB_B64}"
else
  python3 - <<PY > "${SUB_DIR}/${SUB_B64}"
import base64,sys
print(base64.b64encode(open(sys.argv[1],'rb').read()).decode('ascii'), end='')
PY
fi

# 6) Clash YAML（最新 Clash 兼容）
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

# 7) 可选 HTTP 服务
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

echo "Clash YAML订阅：http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_CLASH}"
echo "单行 URI：http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_PLAIN}"
echo "Base64：http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_B64}"
