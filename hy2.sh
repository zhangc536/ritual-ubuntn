#!/usr/bin/env bash
# hy2.sh — 安装并配置 Hysteria2，同时生成 Clash 可直接导入的订阅 URL
# 适用于 Debian/Ubuntu 系统（需 root 权限）
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
SUB_DIR="/etc/hysteria"                  # 订阅/配置存放目录
SUB_PLAIN="subscription.txt"             # 明文单行 URI
SUB_B64="subscription.b64"               # Base64 单行
SUB_CLASH="subscription_clash.yml"       # Clash YAML 订阅文件名
# ---------------------------------------------------------

# 防火墙控制
UFW_DISABLE="${UFW_DISABLE:-0}"          # 1 跳过所有 ufw 操作；0 正常执行

# 简单输出函数
info(){ printf "\e[34m[INFO]\e[0m %s\n" "$*"; }
warn(){ printf "\e[33m[WARN]\e[0m %s\n" "$*"; }
err(){ printf "\e[31m[ERR]\e[0m %s\n" "$*"; exit 1; }

# 0) 检查 root
if [ "$(id -u)" -ne 0 ]; then
  err "请以 root 用户运行此脚本（或使用 sudo）"
fi

# 1) 获取公网 IPv4（尽量自动）
IPV4="$(ip -4 addr show scope global | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"
[ -n "${IPV4}" ] || err "未检测到公网 IPv4 地址，请在有公网 IPv4 的机器上运行"
info "检测到公网 IPv4：${IPV4}"

# 2) 选择免域名（sslip.io / nip.io）
IP_DASH="${IPV4//./-}"
DOMAIN="${IP_DASH}.sslip.io"
# 验证解析是否到本机
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

# 3) 安装依赖（curl jq openssl python3 ufw 等）
info "安装必要依赖（若已安装会跳过）..."
apt-get update -y
DEPS=(curl jq openssl python3 python3-pip ca-certificates)
for p in "${DEPS[@]}"; do
  if ! dpkg -s "$p" >/dev/null 2>&1; then
    apt-get install -y "$p"
  fi
done

# 安装 ufw 可选（若存在则后面处理）
if ! dpkg -s ufw >/dev/null 2>&1; then
  apt-get install -y ufw || true
fi

# 4) 下载并安装 hysteria（如果尚未安装）
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
    warn "无法通过 GitHub API 获取最新版本标签，将使用 github releases 页面最新链接（可能失败）"
    LATEST_TAG="latest"
  fi
  URL="https://github.com/apernet/hysteria/releases/download/${LATEST_TAG}/${ASSET}"
  curl -fsSL "${URL}" -o /usr/local/bin/hysteria || curl -fsSL "https://github.com/apernet/hysteria/releases/download/${LATEST_TAG}/${ASSET}" -o /usr/local/bin/hysteria || err "下载 hysteria 失败，请手动检查网络或 GitHub Releases"
  chmod +x /usr/local/bin/hysteria
fi
info "hysteria 已安装：$(command -v hysteria)"

# 5) 生成密码（若未传入）
if [ -z "${HY2_PASS}" ]; then
  HY2_PASS="$(openssl rand -hex 16)"
  info "自动生成 HY2 密码"
fi
if [ -z "${OBFS_PASS}" ]; then
  OBFS_PASS="$(openssl rand -hex 8)"
  info "自动生成 obfs 密码"
fi

# 6) 写配置目录与 config.yaml
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

# 7) systemd 服务：hysteria-server
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

# 8) 防火墙（简单放行，带跳过与超时保护）
if [ "${UFW_DISABLE}" = "1" ]; then
info "跳过 ufw 配置（UFW_DISABLE=1）"
else
info "配置 ufw 放行端口..."

# 使用 timeout 防止 ufw 阻塞（注意：--force 仅用于 enable/reset，不用于 allow）
timeout 5s ufw allow 22/tcp >/dev/null 2>&1 || true
timeout 5s ufw allow "${HY2_PORT}"/udp >/dev/null 2>&1 || true
timeout 5s ufw allow 80/tcp >/dev/null 2>&1 || true
timeout 5s ufw allow "${SUB_PORT}"/tcp >/dev/null 2>&1 || true
timeout 5s ufw --force enable >/dev/null 2>&1 || true
fi

# 9) 构造 hysteria2:// 单行 URI（备份）
# 用简单 URL 编码处理密码与名字（避免特殊字符问题）
url_encode() {
  python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"
}
PASS_ENC="$(url_encode "${HY2_PASS}")"
OBFS_ENC="$(url_encode "${OBFS_PASS}")"
NAME_ENC="$(url_encode "${NAME_TAG}")"
PIN_ENC="$(url_encode "${PIN_SHA256}")"

URI="hysteria2://${PASS_ENC}@${DOMAIN}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"

# 写入明文与 base64
printf '%s\n' "${URI}" > "${SUB_DIR}/${SUB_PLAIN}"
chmod 644 "${SUB_DIR}/${SUB_PLAIN}"

# Base64 单行（无换行）
if base64 --help >/dev/null 2>&1 && base64 -w 0 >/dev/null 2>&1; then
  base64 -w 0 "${SUB_DIR}/${SUB_PLAIN}" > "${SUB_DIR}/${SUB_B64}"
else
  python3 - <<PY > "${SUB_DIR}/${SUB_B64}"
import base64
print(base64.b64encode(open('${SUB_DIR}/${SUB_PLAIN}','rb').read()).decode('ascii'), end='')
PY
fi
chmod 644 "${SUB_DIR}/${SUB_B64}"

# 10) 生成 Clash YAML（兼容 Clash / Clash.Meta / ClashX 等）
CLASH_PATH="${SUB_DIR}/${SUB_CLASH}"
cat > "${CLASH_PATH}" <<EOF
# Auto-generated Clash subscription (single hysteria node)
# 可将此 URL 添加到 Clash / Clash Meta 的订阅（Providers）中直接导入节点
proxies:
  - name: "${NAME_TAG}"
    type: hysteria
    server: "${DOMAIN}"
    port: ${HY2_PORT}
    # 常见字段名兼容性：auth-str / auth_str / password
    auth-str: "${HY2_PASS}"
    auth_str: "${HY2_PASS}"
    password: "${HY2_PASS}"
    obfs: "${OBFS_PASS}"
    # 协议：udp / faketcp / wechat-video 等（多数场景使用 udp）
    protocol: "udp"
    sni: "${DOMAIN}"
    # 跳过证书验证（有的客户端字段名不同，均写上以提高兼容）
    skip-cert-verify: false
    skip_cert_verify: false
    # 可选性能字段（某些客户端会解析）
    udp: true
    # 可选限速元信息（仅作显示，非所有客户端支持）
    up: "30 Mbps"
    down: "200 Mbps"

proxy-groups:
  - name: "Auto"
    type: select
    proxies:
      - "${NAME_TAG}"

# 其他（空），部分客户端会读取 providers 字段
proxy-providers: {}
EOF
chmod 644 "${CLASH_PATH}"
info "已生成 Clash 订阅文件：${CLASH_PATH}"

# 11) 如果启用订阅发布，创建 systemd 服务用于 /etc/hysteria 目录的简单 HTTP 服务
if [ "${SUB_ENABLE}" != "0" ]; then
  cat >/etc/systemd/system/hysteria-sub.service <<'SVC'
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
    info "订阅 HTTP 服务已启动（${SUB_PORT}）"
  fi
fi

# 12) 显示最终信息与订阅 URL
echo
echo "========================================"
echo "Hysteria 节点信息（Clash 可用）"
echo
echo "Clash 订阅 URL（直接导入 Clash）:"
if [ "${SUB_ENABLE}" != "0" ]; then
  echo "  http://${DOMAIN}:${SUB_PORT}/${SUB_CLASH}"
else
  echo "  (订阅发布已关闭，订阅文件位于 ${CLASH_PATH})"
fi
echo
if [ "${SUB_ENABLE}" != "0" ]; then
  echo "明文单行 URI（备用）:  http://${DOMAIN}:${SUB_PORT}/${SUB_PLAIN}"
  echo "Base64 单行（备用）:  http://${DOMAIN}:${SUB_PORT}/${SUB_B64}"
else
  echo "明文单行 URI（本地）:  ${SUB_DIR}/${SUB_PLAIN}"
  echo "Base64 单行（本地）:  ${SUB_DIR}/${SUB_B64}"
fi
echo
echo "注意：首次与续期均需要 80/tcp 可达（HTTP-01）。"
echo "如果你想改用 HTTPS 来发布订阅，请告诉我，我可以把脚本改成用 Caddy 自动 TLS。"
echo "========================================"
fi
