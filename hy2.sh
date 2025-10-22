#!/usr/bin/env bash
# HY2 (Hysteria2) on IPv4-only VPS WITHOUT own domain & WITHOUT email
# Uses <IP>.sslip.io (fallback: <IP>.nip.io) + ACME HTTP-01 (needs TCP/80 reachable).
# Prints a single hysteria2:// node (no up/down params).
set -euo pipefail

# ===== 可改参数（也可用环境变量覆盖）=====
HY2_PORT="${HY2_PORT:-8443}"          # HY2 监听的 UDP 端口
HY2_PASS="${HY2_PASS:-}"              # 认证密码（留空自动生成）
OBFS_PASS="${OBFS_PASS:-}"            # salamander 混淆密码（留空自动生成）
NAME_TAG="${NAME_TAG:-MyHysteria}"    # URL 末尾 #名称
PIN_SHA256="${PIN_SHA256:-}"          # 证书指纹（可留空）

# 订阅发布（可选）
SUB_ENABLE="${SUB_ENABLE:-1}"          # 1 启用内置 HTTP 订阅发布；0 仅生成本地文件
SUB_PORT="${SUB_PORT:-8080}"           # 订阅 HTTP 端口
SUB_DIR="${SUB_DIR:-/etc/hysteria}"    # 订阅/配置目录
SUB_PLAIN="${SUB_PLAIN:-subscription.txt}"
SUB_B64="${SUB_B64:-subscription.b64}"
SUB_CLASH="${SUB_CLASH:-subscription_clash.yml}"
# =====================================

# 0) 必须有公网 IPv4
IPV4="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
[ -n "$IPV4" ] || { echo "[ERR] 未检测到公网 IPv4"; exit 1; }

# 1) 依赖
export DEBIAN_FRONTEND=noninteractive
pkgs=(curl jq openssl ufw python3)
for b in "${pkgs[@]}"; do
  if ! command -v "$b" >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y "${pkgs[@]}"
    break
  fi
done

# 2) 生成零配置域名（优先 sslip.io；失败用 nip.io）
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

# 3) 确认 80 端口空闲（HTTP-01 必须）
if ss -ltn '( sport = :80 )' | grep -q ':80'; then
  echo "[ERR] 80/tcp 已被占用（HTTP-01 需要临时监听 80）。请先停用占用服务后再运行。"
  exit 1
fi

# 4) 安装 Hysteria2
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

# 5) 生成密码
[[ -n "$HY2_PASS"  ]] || HY2_PASS="$(openssl rand -hex 16)"
[[ -n "$OBFS_PASS" ]] || OBFS_PASS="$(openssl rand -hex 8)"

# 6) 写 HY2 配置（启用 salamander；ACME 走 HTTP-01；不写 email 字段）
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
  # HTTP-01：Hysteria 会临时监听 80/tcp 完成验证
  disable_http_challenge: false
  disable_tlsalpn_challenge: true
EOF

# 7) systemd 服务（仅 HY2）
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

# 8) 防火墙（UFW）
if command -v ufw >/dev/null 2>&1; then
  sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw || true
  ufw allow 22
  ufw allow ${HY2_PORT}/udp || true
  ufw allow 80/tcp || true
  # 如果启用订阅服务，放行订阅端口
  if [ "${SUB_ENABLE}" = "1" ]; then
    ufw allow ${SUB_PORT}/tcp || true
  fi
  yes | ufw enable >/dev/null 2>&1 || true
fi

# 9) 启动
systemctl daemon-reload
systemctl enable --now hysteria-server
sleep 1

echo "=== 监听检查（UDP/${HY2_PORT}) ==="
ss -lunp | grep -E ":${HY2_PORT}\b" || true

# 10) 构造节点（无 up/down；敏感字段 URL 编码）
enc() { python3 - <<'PY' "$1"
import sys, urllib.parse as u
print(u.quote(sys.argv[1], safe=''))
PY
}
PASS_ENC="$(enc "$HY2_PASS")"
OBFS_ENC="$(enc "$OBFS_PASS")"
NAME_ENC="$(enc "$NAME_TAG")"
PIN_ENC="$(enc "$PIN_SHA256")"  # 可为空

# 输出为：hysteria2://<pass>@<host>:<port>/?protocol=udp&obfs=salamander&obfs-password=<>&sni=<>&insecure=0&pinSHA256=<>#Name
URI="hysteria2://${PASS_ENC}@${HY2_DOMAIN}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"

echo
echo "=========== HY2 节点（无邮箱/无 up/down） ==========="
echo "${URI}"
echo "==================================================="

# 11) 生成订阅文件（单行 URI + Base64 + Clash YAML）
install -d -m 755 "${SUB_DIR}"
printf '%s\n' "${URI}" > "${SUB_DIR}/${SUB_PLAIN}"
chmod 644 "${SUB_DIR}/${SUB_PLAIN}"

# base64（单行，无换行）
if base64 --help >/dev/null 2>&1 && base64 -w 0 </dev/null >/dev/null 2>&1; then
  base64 -w 0 "${SUB_DIR}/${SUB_PLAIN}" > "${SUB_DIR}/${SUB_B64}"
else
  python3 - <<PY > "${SUB_DIR}/${SUB_B64}"
import base64,sys
print(base64.b64encode(open(sys.argv[1],'rb').read()).decode('ascii'), end='')
PY
fi
chmod 644 "${SUB_DIR}/${SUB_B64}"

# Clash YAML（兼容字段）
CLASH_PATH="${SUB_DIR}/${SUB_CLASH}"
cat >"${CLASH_PATH}" <<EOF
# Auto-generated Clash subscription (single hysteria node)
proxies:
  - name: "${NAME_TAG}"
    type: hysteria
    server: "${HY2_DOMAIN}"
    port: ${HY2_PORT}
    auth-str: "${HY2_PASS}"
    auth_str: "${HY2_PASS}"
    password: "${HY2_PASS}"
    obfs: "${OBFS_PASS}"
    protocol: "udp"
    sni: "${HY2_DOMAIN}"
    skip-cert-verify: false
    skip_cert_verify: false
    udp: true

proxy-groups:
  - name: "Auto"
    type: select
    proxies:
      - "${NAME_TAG}"

proxy-providers: {}
EOF
chmod 644 "${CLASH_PATH}"

# 12) 可选：暴露 HTTP 订阅目录
if [ "${SUB_ENABLE}" = "1" ]; then
  cat >/etc/systemd/system/hysteria-sub.service <<SVC
[Unit]
Description=Simple HTTP server to serve Hysteria subscription files
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
echo "=========== Clash 订阅链接（可直接导入） ==========="
if [ "${SUB_ENABLE}" = "1" ]; then
  echo "Clash YAML 订阅："
  echo "  http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_CLASH}"
  echo
  echo "其他格式订阅："
  echo "  单行 URI：http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_PLAIN}"
  echo "  Base64：  http://${HY2_DOMAIN}:${SUB_PORT}/${SUB_B64}"
  echo
  echo "使用方法："
  echo "  1. 复制上面的 Clash YAML 链接"
  echo "  2. 在 Clash 客户端中添加订阅"
  echo "  3. 或直接访问链接下载配置文件"
else
  echo "订阅文件已生成本地（HTTP 服务未启用）："
  echo "  Clash YAML：${CLASH_PATH}"
  echo "  单行 URI：  ${SUB_DIR}/${SUB_PLAIN}"
  echo "  Base64：    ${SUB_DIR}/${SUB_B64}"
  echo
  echo "如需启用 HTTP 订阅服务，请设置 SUB_ENABLE=1"
fi
echo "=================================================="
echo
echo "提示：首次与续期均需 80/tcp 外网可达（HTTP-01）。"
echo "如果你需要 HTTPS 方式公开订阅，我可以改用 Caddy 提供自动 TLS。"
