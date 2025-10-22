#!/usr/bin/env bash
# hy2.sh — 安装并配置 Hysteria2，同时生成 Clash 可直接导入的订阅 URL
# 适用于 Debian/Ubuntu 系统（需 root 权限）
# 特点：稳健处理 ufw（防卡住），可用 UFW_DISABLE=1 跳过 ufw 步骤
set -euo pipefail

# ---------------- 可配置项（环境变量覆盖） ----------------
HY2_PORT="${HY2_PORT:-8443}"             # hysteria UDP 监听端口
HY2_PASS="${HY2_PASS:-}"                 # hysteria 密码（不填自动生成）
OBFS_PASS="${OBFS_PASS:-}"               # salamander 混淆密码（不填自动生成）
NAME_TAG="${NAME_TAG:-Hysteria-Node}"    # Clash 中显示的节点名
PIN_SHA256="${PIN_SHA256:-}"             # 可选证书 pin（留空 OK）

# 订阅发布相关
SUB_ENABLE="${SUB_ENABLE:-1}"            # 是否启用 HTTP 发布订阅（1 启用，0 不启用）
SUB_PORT="${SUB_PORT:-8080}"             # 订阅 HTTP 服务端口
SUB_DIR="${SUB_DIR:-/etc/hysteria}"      # 订阅/配置存放目录
SUB_PLAIN="${SUB_PLAIN:-subscription.txt}"   # 明文单行 URI
SUB_B64="${SUB_B64:-subscription.b64}"       # Base64 单行
SUB_CLASH="${SUB_CLASH:-subscription_clash.yml}" # Clash YAML 订阅文件名
# ---------------------------------------------------------

# 输出函数
info(){ printf "\e[34m[INFO]\e[0m %s\n" "$*"; }
warn(){ printf "\e[33m[WARN]\e[0m %s\n" "$*"; }
err(){ printf "\e[31m[ERR]\e[0m %s\n" "$*"; exit 1; }

# 必须以 root 运行
if [ "$(id -u)" -ne 0 ]; then
  err "请以 root 用户运行此脚本（或使用 sudo）"
fi

# 获取公网 IPv4（尽量自动）
IPV4="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
[ -n "${IPV4}" ] || err "未检测到公网 IPv4 地址，请在有公网 IPv4 的机器上运行"
info "检测到公网 IPv4：${IPV4}"

# 选择免域名（sslip.io / nip.io）
IP_DASH="${IPV4//./-}"
DOMAIN="${IP_DASH}.sslip.io"
RES="$(getent ahostsv4 "${DOMAIN}" | awk '{print $1}' | head -n1 || true)"
if [ "${RES}" != "${IPV4}" ] || [ -z "${RES}" ]; then
  ALT="${IP_DASH}.nip.io"
  RES2="$(getent ahostsv4 "${ALT}" | awk '{print $1}' | head -n1 || true)"
  if [ "${RES2}" = "${IPV4}" ]; then
    DOMAIN="${ALT}"
  else
    warn "sslip.io / nip.io 未解析到本机 IP，仍会继续使用 ${DOMAIN}，但请确保外部能解析该域名到本机 IP"
  fi
fi
info "使用域名：${DOMAIN}"

# 安装基本依赖
info "安装必要依赖（若已安装会跳过）..."
apt-get update -y
DEPS=(curl jq openssl python3 python3-pip ca-certificates)
for p in "${DEPS[@]}"; do
  if ! dpkg -s "$p" >/dev/null 2>&1; then
    apt-get install -y "$p"
  fi
done

# 安装 ufw（非强制）
if ! dpkg -s ufw >/dev/null 2>&1; then
  info "检测到系统未安装 ufw，尝试安装（可通过 UFW_DISABLE=1 跳过）..."
  apt-get install -y ufw || warn "安装 ufw 失败，脚本会在后续跳过 ufw 步骤"
fi

# 安装 hysteria（二进制）
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
    warn "无法通过 GitHub API 获取最新版本标签，将尝试使用 latest 标记的下载链接"
    LATEST_TAG="latest"
  fi
  URL="https://github.com/apernet/hysteria/releases/download/${LATEST_TAG}/${ASSET}"
  if ! curl -fsSL "${URL}" -o /usr/local/bin/hysteria; then
    err "下载 hysteria 失败，请手动检查网络或 GitHub Releases"
  fi
  chmod +x /usr/local/bin/hysteria
fi
info "hysteria 就绪：$(command -v hysteria)"

# 自动生成密码（若未提供）
if [ -z "${HY2_PASS}" ]; then
  HY2_PASS="$(openssl rand -hex 16)"
  info "自动生成 HY2 密码"
fi
if [ -z "${OBFS_PASS}" ]; then
  OBFS_PASS="$(openssl rand -hex 8)"
  info "自动生成 obfs 密码"
fi

# 写配置目录与 config.yaml
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

# systemd 服务（hysteria）
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

# ----------------- 稳健版 ufw 配置（避免交互阻塞） -----------------
if [ "${UFW_DISABLE:-0}" = "1" ]; then
  info "检测到 UFW_DISABLE=1，跳过 ufw 配置"
else
  if command -v ufw >/dev/null 2>&1; then
    info "配置 ufw 放行端口（使用稳健方法以避免卡住）"

    # 安全执行 ufw（使用 timeout 若可用，并断开 stdin）
    safe_ufw() {
      # 参数传入完整 ufw 子命令字符串，例如: "allow 22/tcp"
      if command -v timeout >/dev/null 2>&1; then
        timeout 12s sh -c "ufw $* </dev/null" >/dev/null 2>&1 || return 1
      else
        sh -c "ufw $* </dev/null" >/dev/null 2>&1 || return 1
      fi
      return 0
    }

    safe_ufw "allow 22/tcp" || warn "ufw allow 22/tcp 失败或超时"
    safe_ufw "allow ${HY2_PORT}/udp" || warn "ufw allow ${HY2_PORT}/udp 失败或超时"
    safe_ufw "allow 80/tcp" || warn "ufw allow 80/tcp 失败或超时"
    safe_ufw "allow ${SUB_PORT}/tcp" || warn "ufw allow ${SUB_PORT}/tcp 失败或超时"

    # 强制启用 ufw（非交互）
    if ! safe_ufw "--force enable"; then
      warn "ufw --force enable 失败或阻塞；你可以手动运行: ufw --force enable"
    fi
  else
    warn "系统中未找到 ufw；若你使用 firewalld 或 iptables，请手动放行端口"
  fi
fi
# --------------------------------------------------------------------

# 构造 hysteria2:// 单行 URI（做 URL 编码）
url_encode() {
  python3 - <<PY
import sys, urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=''))
PY
}
PASS_ENC="$(url_encode "${HY2_PASS}")"
OBFS_ENC="$(url_encode "${OBFS_PASS}")"
NAME_ENC="$(url_encode "${NAME_TAG}")"
PIN_ENC="$(url_encode "${PIN_SHA256}")"

URI="hysteria2://${PASS_ENC}@${DOMAIN}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"

# 写入明文与 base64（无换行）
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

# 生成 Clash YAML（更高兼容性：多个别名字段）
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

# 订阅 HTTP 服务（simple python http.server）
if [ "${SUB_ENABLE}" != "0" ]; then
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
  if ! systemctl enable --now hysteria-sub.service; then
    warn "启动 hysteria-sub.service 失败（可能端口 ${SUB_PORT} 被占用），请手动检查"
  else
    info "订阅 HTTP 服务已启动（端口 ${SUB_PORT}）"
  fi
fi

# 最终输出
echo
echo "========================================"
echo "Hysteria 节点信息（Clash 可用）"
echo
if [ "${SUB_ENABLE}" != "0" ]; then
  echo "Clash 订阅 URL（直接导入 Clash）:"
  echo "  http://${DOMAIN}:${SUB_PORT}/${SUB_CLASH}"
else
  echo "Clash 订阅文件位于： ${CLASH_PATH} （未对外发布）"
fi
echo
echo "明文单行 URI（备用）:  http://${DOMAIN}:${SUB_PORT}/${SUB_PLAIN}"
echo "Base64 单行（备用）:  http://${DOMAIN}:${SUB_PORT}/${SUB_B64}"
echo
echo "提示：首次与续期需 80/tcp 可达（HTTP-01）。"
echo "如需使用 HTTPS 发布订阅（推荐），我可把脚本改为使用 Caddy 自动 TLS。"
echo "========================================"
