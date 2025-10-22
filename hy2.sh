#!/usr/bin/env bash
# hy2.sh — 安装并配置 Hysteria2，并生成 Clash 可直接导入的订阅（不自动启用 ufw，避免卡住）
# 用法: sudo ./hy2.sh
# 如需脚本尝试配置 ufw（可能会在某些系统卡住），运行: sudo UFW_DISABLE=0 ./hy2.sh
set -euo pipefail

# ---------------- 可配置项（可用环境变量覆盖） ----------------
UFW_DISABLE="${UFW_DISABLE:-1}"           # 默认 1：跳过 ufw；设为 0 则尝试配置 ufw（非交互）
HY2_PORT="${HY2_PORT:-8443}"             # Hysteria UDP 监听端口
HY2_PASS="${HY2_PASS:-}"                 # Hysteria 密码（留空自动生成）
OBFS_PASS="${OBFS_PASS:-}"               # Salamander obfs 密码（留空自动生成）
NAME_TAG="${NAME_TAG:-Hysteria-Node}"    # Clash 节点名
PIN_SHA256="${PIN_SHA256:-}"             # 可选证书 pin

SUB_ENABLE="${SUB_ENABLE:-1}"            # 是否启用 HTTP 发布订阅 (1=启用)
SUB_PORT="${SUB_PORT:-8080}"             # 订阅 HTTP 服务端口
SUB_DIR="${SUB_DIR:-/etc/hysteria}"      # 所有配置/订阅文件目录
SUB_PLAIN="${SUB_PLAIN:-subscription.txt}"
SUB_B64="${SUB_B64:-subscription.b64}"
SUB_CLASH="${SUB_CLASH:-subscription_clash.yml}"
# ---------------------------------------------------------

info(){ printf "\e[34m[INFO]\e[0m %s\n" "$*"; }
warn(){ printf "\e[33m[WARN]\e[0m %s\n" "$*"; }
err(){ printf "\e[31m[ERR]\e[0m %s\n" "$*"; exit 1; }

# 必须 root
if [ "$(id -u)" -ne 0 ]; then
  err "请以 root 用户运行（sudo ./hy2.sh）"
fi

# 获取公网 IPv4（尽量自动）
IPV4="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
if [ -z "${IPV4}" ]; then
  warn "未检测到公网 IPv4（脚本仍会继续，但请确认你的 VPS 有公网地址）"
else
  info "检测到公网 IPv4：${IPV4}"
fi

# 选择免域名 (sslip.io / nip.io)
if [ -n "${IPV4}" ]; then
  IP_DASH="${IPV4//./-}"
  DOMAIN="${IP_DASH}.sslip.io"
  # 验证解析是否到本机（不强制）
  RES="$(getent ahostsv4 "${DOMAIN}" | awk '{print $1}' | head -n1 || true)"
  if [ "${RES}" != "${IPV4}" ] || [ -z "${RES}" ]; then
    ALT="${IP_DASH}.nip.io"
    RES2="$(getent ahostsv4 "${ALT}" | awk '{print $1}' | head -n1 || true)"
    if [ "${RES2}" = "${IPV4}" ]; then
      DOMAIN="${ALT}"
    else
      warn "sslip.io / nip.io 解析可能未指向本机，脚本仍用 ${DOMAIN}（请确保外部能解析到本机 IP）"
    fi
  fi
else
  DOMAIN="127-0-0-1.sslip.io"
fi
info "使用域名：${DOMAIN}"

# 安装依赖
info "安装必要依赖（若已存在会跳过）..."
apt-get update -y
DEPS=(curl jq openssl python3 ca-certificates)
for p in "${DEPS[@]}"; do
  if ! dpkg -s "$p" >/dev/null 2>&1; then
    apt-get install -y "$p"
  fi
done

# 尝试安装 ufw（但默认不会启用），若你设 UFW_DISABLE=0，脚本会尝试使用它
if [ "${UFW_DISABLE}" -eq 0 ]; then
  if ! dpkg -s ufw >/dev/null 2>&1; then
    info "尝试安装 ufw..."
    apt-get install -y ufw || warn "安装 ufw 失败，将继续但不会配置 ufw"
  fi
else
  info "默认跳过 ufw 操作（如需启用，使用 UFW_DISABLE=0）"
fi

# 安装 hysteria 可执行文件（若不存在）
if ! command -v hysteria >/dev/null 2>&1; then
  info "下载并安装 hysteria 二进制..."
  ARCH="$(uname -m)"
  case "${ARCH}" in
    x86_64|amd64) ASSET="hysteria-linux-amd64" ;;
    aarch64|arm64) ASSET="hysteria-linux-arm64" ;;
    *) ASSET="hysteria-linux-amd64" ;;
  esac
  LATEST_TAG="$(curl -fsSL https://api.github.com/repos/apernet/hysteria/releases/latest | jq -r '.tag_name' 2>/dev/null || true)"
  if [ -z "${LATEST_TAG}" ] || [ "${LATEST_TAG}" = "null" ]; then
    warn "无法通过 GitHub API 获取最新版本标签，使用 'latest' 试下载"
    LATEST_TAG="latest"
  fi
  URL="https://github.com/apernet/hysteria/releases/download/${LATEST_TAG}/${ASSET}"
  if ! curl -fsSL "${URL}" -o /usr/local/bin/hysteria; then
    err "下载 hysteria 失败，请手动检查网络或 GitHub Releases"
  fi
  chmod +x /usr/local/bin/hysteria
fi
info "hysteria 已就绪：$(command -v hysteria)"

# 密码生成（若未提供）
if [ -z "${HY2_PASS}" ]; then
  HY2_PASS="$(openssl rand -hex 16)"
  info "自动生成 HY2 密码"
fi
if [ -z "${OBFS_PASS}" ]; then
  OBFS_PASS="$(openssl rand -hex 8)"
  info "自动生成 obfs 密码"
fi

# 写 Hysteria 配置文件
mkdir -p "${SUB_DIR}"
cat > "${SUB_DIR}/config.yaml" <<EOF
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
    - ${DOMAIN}
  disable_http_challenge: false
  disable_tlsalpn_challenge: true
EOF
chmod 600 "${SUB_DIR}/config.yaml"
info "已写入 Hysteria 配置：${SUB_DIR}/config.yaml"

# systemd 单元：hysteria-server
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
sleep 1
info "hysteria-server 已启动（systemd）"

# 如果用户希望脚本尝试配置 ufw，则安全尝试（非交互）
if [ "${UFW_DISABLE}" -eq 0 ] && command -v ufw >/dev/null 2>&1; then
  info "尝试非交互配置 ufw 放行所需端口..."
  ufw --force allow 22/tcp >/dev/null 2>&1 || warn "ufw: 添加 22/tcp 规则失败"
  ufw --force allow "${HY2_PORT}"/udp >/dev/null 2>&1 || warn "ufw: 添加 ${HY2_PORT}/udp 规则失败"
  ufw --force allow 80/tcp >/dev/null 2>&1 || warn "ufw: 添加 80/tcp 规则失败"
  ufw --force allow "${SUB_PORT}"/tcp >/dev/null 2>&1 || warn "ufw: 添加 ${SUB_PORT}/tcp 规则失败"
  if ufw --force enable </dev/null >/dev/null 2>&1; then
    info "ufw 已启用"
  else
    warn "ufw 启用失败或被阻塞；请手动检查 ufw 状态"
  fi
fi

# URL encode helper — 将参数作为 argv[1] 传给 python
url_encode() {
  python3 - <<PY "$1"
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
}

PASS_ENC="$(url_encode "${HY2_PASS}")"
OBFS_ENC="$(url_encode "${OBFS_PASS}")"
NAME_ENC="$(url_encode "${NAME_TAG}")"
PIN_ENC="$(url_encode "${PIN_SHA256}")"

# 构造 hysteria2 URI
URI="hysteria2://${PASS_ENC}@${DOMAIN}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"

# 写明文与 Base64（单行）
printf '%s\n' "${URI}" > "${SUB_DIR}/${SUB_PLAIN}"
chmod 644 "${SUB_DIR}/${SUB_PLAIN}"

if base64 --help >/dev/null 2>&1 && base64 -w 0 >/dev/null 2>&1; then
  base64 -w 0 "${SUB_DIR}/${SUB_PLAIN}" > "${SUB_DIR}/${SUB_B64}"
else
  python3 - <<PY > "${SUB_DIR}/${SUB_B64}"
import base64
print(base64.b64encode(open('${SUB_DIR}/${SUB_PLAIN}','rb').read()).decode('ascii'), end='')
PY
fi
chmod 644 "${SUB_DIR}/${SUB_B64}"
info "写入明文与 Base64 订阅文件"

# 生成 Clash 格式 YAML（增加别名字段提高兼容）
CLASH_PATH="${SUB_DIR}/${SUB_CLASH}"
cat > "${CLASH_PATH}" <<EOF
# Auto-generated Clash subscription (single hysteria node)
proxies:
  - name: "${NAME_TAG}"
    type: hysteria
    server: "${DOMAIN}"
    port: ${HY2_PORT}
    auth-str: "${HY2_PASS}"
    auth_str: "${HY2_PASS}"
    password: "${HY2_PASS}"
    obfs: "${OBFS_PASS}"
    protocol: "udp"
    sni: "${DOMAIN}"
    skip-cert-verify: false
    skip_cert_verify: false
    udp: true
    up: "30 Mbps"
    down: "200 Mbps"

proxy-groups:
  - name: "Auto"
    type: select
    proxies:
      - "${NAME_TAG}"

proxy-providers: {}
EOF
chmod 644 "${CLASH_PATH}"
info "已生成 Clash 订阅文件：${CLASH_PATH}"

# 创建并启动订阅发布服务（simple HTTP server）
if [ "${SUB_ENABLE}" -ne 0 ]; then
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
  if systemctl enable --now hysteria-sub.service; then
    info "订阅 HTTP 服务已启动（端口 ${SUB_PORT}）"
  else
    warn "启动 hysteria-sub.service 失败（可能端口被占用），请检查 systemctl status hysteria-sub"
  fi
else
  info "SUB_ENABLE=0，已生成订阅文件但未启动 HTTP 服务"
fi

# 输出最终信息（尝试打印外网 IP 或域名）
echo
echo "========================================"
echo "Hysteria 节点/订阅 信息："
if [ "${SUB_ENABLE}" -ne 0 ]; then
  # 尝试获取公网 IP 做展示（如果可用）
  OUT_IP="$(curl -sS -4 ifconfig.co 2>/dev/null || true)"
  if [ -n "${OUT_IP}" ]; then
    DISPLAY_HOST="${OUT_IP}"
  else
    DISPLAY_HOST="${DOMAIN}"
  fi
  echo "Clash 订阅 URL: http://${DISPLAY_HOST}:${SUB_PORT}/${SUB_CLASH}"
  echo "Plain URI:       http://${DISPLAY_HOST}:${SUB_PORT}/${SUB_PLAIN}"
  echo "Base64:          http://${DISPLAY_HOST}:${SUB_PORT}/${SUB_B64}"
else
  echo "Clash 订阅文件已写入： ${CLASH_PATH}"
  echo "明文/Base64 文件： ${SUB_DIR}/${SUB_PLAIN} , ${SUB_DIR}/${SUB_B64}"
fi
echo
echo "注意：首次及续期证书需要 80/tcp 可达（HTTP-01）。"
echo "若需要脚本自动配置 ufw，请用 UFW_DISABLE=0 运行（部分系统可能卡住），或手动使用 iptables/firewalld 放行端口。"
echo "========================================"
