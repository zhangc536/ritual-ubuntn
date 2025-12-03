#!/usr/bin/env bash
set -euo pipefail

# =============================================================
# 脚本顺序概览（执行主流程）：
#  0) 选择模式（全新安装 / 仅维护任务）
#  1) 获取公网 IPv4
#  2) 安装依赖（如缺失）
#  3) 域名处理（支持自定义域名；已移除动态域名服务）
#  4) 安装 hysteria 二进制（若不存在）
#  5) 生成主/多端口密码与端口列表（如未提供）
#  6) 检查 /acme 现有证书；否则准备 ACME（并确保 80/tcp 可用）
#  7) 写主端口与多端口配置（TLS 或 ACME）并启动（systemd 或直接模式回退）
#  8) 等待 ACME 完成，尝试从常见路径导入证书（Nginx/Apache/Caddy/Traefik 等）
#  9) 恢复 80/tcp 上被暂时停止的服务
# 10) 打印进程与监听检查、构造 URI、生成 Clash 订阅并通过 Nginx 提供
#
# 说明：所有 helper 函数在前置定义；主流程按以上顺序执行，避免“未定义函数”或“端口占用”导致失败。
# =============================================================

# ===== 可改参数 =====
HY2_PORT="${HY2_PORT:-8443}"          # Hysteria2 UDP端口
HY2_PORTS="${HY2_PORTS:-}"            # 多端口（逗号分隔，例如 8443,8444,8445）
HY2_PORT_COUNT="${HY2_PORT_COUNT:-}"  # 端口数量（若未提供 HY2_PORTS，则按数量从主端口递增）
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
  printf '%s' "$1" | sed -e 's@[\/&@]@\\&@g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
}

# ---- helper: 若未提供 HY2_PORTS，则交互式询问端口数量并生成列表 ----
maybe_init_ports_from_input() {
  # 已提供 HY2_PORTS 时直接跳过
  if [ -n "${HY2_PORTS:-}" ]; then
    return 0
  fi

  local count="${HY2_PORT_COUNT:-}"
  # 在交互式终端时询问数量
  if [ -z "$count" ] && [ -t 0 ]; then
    read -r -p "请输入需要的端口数量（默认 1，最大 30）：" count || true
  fi

  case "${count:-}" in
    "" ) count=1 ;;
    *[!0-9]* ) count=1 ;;
  esac

  if [ "$count" -lt 1 ]; then count=1; fi
  if [ "$count" -gt 30 ]; then count=30; fi

  # 按数量从主端口递增生成列表（包含主端口本身）
  local base="$HY2_PORT"
  local out="$base"
  local i=1
  while [ "$i" -lt "$count" ]; do
    local next=$((base + i))
    if [ "$next" -gt 65535 ]; then break; fi
    out="${out},${next}"
    i=$((i + 1))
  done
  HY2_PORTS="$out"
  echo "[OK] 已选择端口列表：${HY2_PORTS}"
}

# ---- helper: 解析端口列表（HY2_PORTS 优先，其次 HY2_PORT） ----
parse_port_list() {
  local raw="${HY2_PORTS:-}"
  local out=""
  if [ -n "$raw" ]; then
    IFS=',' read -r -a parts <<<"$raw"
    for p in "${parts[@]}"; do
      p="$(echo "$p" | tr -d ' ' )"
      if echo "$p" | grep -Eq '^[0-9]{2,5}$'; then
        case ",$out," in
          *",$p,"*) ;;
          *) out="${out:+$out,}$p" ;;
        esac
      fi
    done
  fi
  if [ -z "$out" ]; then
    out="$HY2_PORT"
  fi
  echo "$out"
}

# ---- helper: 为每端口生成凭据（若未提供） ----
gen_credentials_for_ports() {
  local list_csv="$1"
  declare -gA PASS_MAP
  declare -gA OBFS_MAP
  IFS=',' read -r -a ports <<<"$list_csv"
  for pt in "${ports[@]}"; do
    local pass obfs
    if [ "$pt" = "$HY2_PORT" ] && [ -n "${HY2_PASS:-}" ]; then
      pass="$HY2_PASS"
    else
      pass="$(openssl rand -hex 16)"
    fi
    if [ "$pt" = "$HY2_PORT" ] && [ -n "${OBFS_PASS:-}" ]; then
      obfs="$OBFS_PASS"
    else
      obfs="$(openssl rand -hex 8)"
    fi
    PASS_MAP[$pt]="$pass"
    OBFS_MAP[$pt]="$obfs"
  done
}

# ---- helper: 写单端口 hysteria 配置到 /etc/hysteria/config-<port>.yaml ----
write_hysteria_config_for_port() {
  local port="$1"; local pass="$2"; local obfsp="$3"; local use_tls="$4"
  mkdir -p /etc/hysteria
  if [ "$use_tls" = "1" ]; then
    cat >"/etc/hysteria/config-${port}.yaml" <<EOF
listen: :${port}
protocol: udp

auth:
  type: password
  password: ${pass}

obfs:
  type: salamander
  salamander:
    password: ${obfsp}

tls:
  cert: ${USE_CERT_PATH}
  key: ${USE_KEY_PATH}
EOF
  else
    mkdir -p /acme/autocert
    cat >"/etc/hysteria/config-${port}.yaml" <<EOF
listen: :${port}
protocol: udp

auth:
  type: password
  password: ${pass}

obfs:
  type: salamander
  salamander:
    password: ${obfsp}

acme:
  domains:
    - ${HY2_DOMAIN}
  dir: /acme/autocert
  type: http
  listenHost: 0.0.0.0
EOF
  fi
}

# ---- helper: 写主端口 /etc/hysteria/config.yaml（TLS 或 ACME） ----
write_hysteria_main_config() {
  local use_tls="$1"
  mkdir -p /etc/hysteria /acme/autocert
  if [ "$use_tls" = "1" ]; then
    cat >/etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}
protocol: udp

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
  else
    cat >/etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}
protocol: udp

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
  dir: /acme/autocert
  type: http
  listenHost: 0.0.0.0
EOF
  fi
}

# ---- helper: 使用 TLS 启动额外端口实例（基于 PORT_LIST_CSV） ----
start_additional_instances_with_tls() {
  [ -n "${HY2_PORTS:-}" ] || return 0
  ensure_systemd_template
  IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
  for pt in "${ports_all[@]}"; do
    [ "$pt" = "$HY2_PORT" ] && continue
    write_hysteria_config_for_port "$pt" "${PASS_MAP[$pt]}" "${OBFS_MAP[$pt]}" "1"
    start_hysteria_instance "$pt"
  done
  ensure_udp_ports_open "$PORT_LIST_CSV"
}

# ---- helper: systemd 模板服务（@）确保存在 ----
ensure_systemd_template() {
  cat >/etc/systemd/system/hysteria-server@.service <<'SVC'
[Unit]
Description=Hysteria Server (config-%i.yaml)
After=network.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config-%i.yaml
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SVC
  systemctl daemon-reload
}

# ---- helper: 启动指定端口的实例 ----
start_hysteria_instance() {
  local port="$1"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now "hysteria-server@${port}" || true
    if ! systemctl is-active --quiet "hysteria-server@${port}"; then
      echo "[WARN] hysteria-server@${port} 未处于 active 状态，输出最近日志以诊断："
      journalctl -u "hysteria-server@${port}" -n 50 --no-pager 2>/dev/null || true
      start_port_service_direct "$port"
    fi
  else
    start_port_service_direct "$port"
  fi
}

# ---- helper: 开放 UDP 端口（firewalld 或 ufw 若存在） ----
ensure_udp_ports_open() {
  local list_csv="$1"
  local opened=0
  if command -v firewall-cmd >/dev/null 2>&1; then
    local changed=0
    IFS=',' read -r -a ports <<<"$list_csv"
    for pt in "${ports[@]}"; do
      firewall-cmd --query-port="${pt}/udp" >/dev/null 2>&1 || { firewall-cmd --add-port="${pt}/udp" --permanent >/dev/null 2>&1 && changed=1; }
    done
    if [ "$changed" -eq 1 ]; then firewall-cmd --reload >/dev/null 2>&1 || true; fi
    echo "[OK] firewalld 已放行指定 UDP 端口"
    opened=1
  elif command -v ufw >/dev/null 2>&1; then
    IFS=',' read -r -a ports <<<"$list_csv"
    for pt in "${ports[@]}"; do
      ufw status 2>/dev/null | grep -q "${pt}/udp" || ufw allow "${pt}/udp" >/dev/null 2>&1 || true
    done
    echo "[OK] ufw 已放行指定 UDP 端口"
    opened=1
  fi
  if [ "$opened" -eq 0 ]; then
    echo "[WARN] 未检测到 firewalld/ufw；若存在其他防火墙或云安全组，请手动放行 UDP 端口。"
  fi
}

# ---- helper: 检查 UDP 端口监听（兼容 ss/netstat/lsof） ----
check_udp_listening() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -lunp | grep -E ":${port}\\b" || true
  elif command -v netstat >/dev/null 2>&1; then
    netstat -anu | grep -E "[\\.:]${port}\\b" || true
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iUDP:${port} || true
  else
    echo "[WARN] 缺少 ss/netstat/lsof，无法检查端口 ${port} 的监听状态"
  fi
}

# ---- helper: 打印 hysteria 进程信息 ----
print_hysteria_process_info() {
  echo "=== 进程检查（hysteria） ==="
  command -v which >/dev/null 2>&1 && which hysteria || true
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -a hysteria || true
  elif command -v ps >/dev/null 2>&1; then
    ps aux | grep -E "[h]ysteria" || true
  else
    echo "[WARN] 缺少 pgrep/ps，无法打印进程信息"
  fi
}

# ---- helper: 直接模式启动（无 systemd 或 systemd 启动失败） ----
start_main_service_direct() {
  mkdir -p /var/log /var/run
  echo "[*] 以直接模式启动主服务（无 systemd）..."
  nohup /usr/local/bin/hysteria server -c /etc/hysteria/config.yaml >/var/log/hysteria-main.log 2>&1 &
  echo $! >/var/run/hysteria-main.pid
  sleep 1
}

start_port_service_direct() {
  local port="$1"
  mkdir -p /var/log /var/run
  echo "[*] 以直接模式启动端口 ${port} 服务（无 systemd）..."
  nohup /usr/local/bin/hysteria server -c "/etc/hysteria/config-${port}.yaml" >/var/log/hysteria-${port}.log 2>&1 &
  echo $! >/var/run/hysteria-${port}.pid
  sleep 1
}

# ---- helper: 开放 TCP 端口（用于 ACME 的 80/tcp） ----
ensure_tcp_port_open() {
  local list_csv="$1"
  local opened=0
  if command -v firewall-cmd >/dev/null 2>&1; then
    local changed=0
    IFS=',' read -r -a ports <<<"$list_csv"
    for pt in "${ports[@]}"; do
      firewall-cmd --query-port="${pt}/tcp" >/dev/null 2>&1 || { firewall-cmd --add-port="${pt}/tcp" --permanent >/dev/null 2>&1 && changed=1; }
    done
    if [ "$changed" -eq 1 ]; then firewall-cmd --reload >/dev/null 2>&1 || true; fi
    echo "[OK] firewalld 已放行指定 TCP 端口"
    opened=1
  elif command -v ufw >/dev/null 2>&1; then
    IFS=',' read -r -a ports <<<"$list_csv"
    for pt in "${ports[@]}"; do
      ufw status 2>/dev/null | grep -q "${pt}/tcp" || ufw allow "${pt}/tcp" >/dev/null 2>&1 || true
    done
    echo "[OK] ufw 已放行指定 TCP 端口"
    opened=1
  fi
  if [ "$opened" -eq 0 ]; then
    echo "[WARN] 未检测到 firewalld/ufw；若存在其他防火墙或云安全组，请手动放行 TCP 端口。"
  fi
}

# ---- helper: 申请 ACME 前确保 80 可用（自动停止 nginx/apache 并开放 80/tcp） ----
STOPPED_NGINX=0
STOPPED_APACHE=0
STOPPED_CADDY=0
STOPPED_TRAEFIK=0
PORT80_FREE=1
ensure_port_80_available() {
  # 开放 80/tcp
  ensure_tcp_port_open "80"

  # 检查并停止常见占用者
  if systemctl is-active --quiet nginx 2>/dev/null; then
    echo "[INFO] 检测到 nginx 正在运行，申请证书将占用 80/tcp，暂时停止 nginx..."
    systemctl stop nginx 2>/dev/null || true
    STOPPED_NGINX=1
  fi
  if systemctl is-active --quiet apache2 2>/dev/null; then
    echo "[INFO] 检测到 apache2 正在运行，申请证书将占用 80/tcp，暂时停止 apache2..."
    systemctl stop apache2 2>/dev/null || true
    STOPPED_APACHE=1
  fi
  if systemctl is-active --quiet caddy 2>/dev/null; then
    echo "[INFO] 检测到 caddy 正在运行，申请证书将占用 80/tcp，暂时停止 caddy..."
    systemctl stop caddy 2>/dev/null || true
    STOPPED_CADDY=1
  fi
  if systemctl is-active --quiet traefik 2>/dev/null; then
    echo "[INFO] 检测到 traefik 正在运行，申请证书将占用 80/tcp，暂时停止 traefik..."
    systemctl stop traefik 2>/dev/null || true
    STOPPED_TRAEFIK=1
  fi

  # 二次检测占用情况
  PORT80_FREE=1
  if command -v ss >/dev/null 2>&1; then
    if ss -ltnp | grep -E "\b:80\b" >/dev/null 2>&1; then PORT80_FREE=0; fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -lntp 2>/dev/null | grep -E "\b:80\b" >/dev/null; then PORT80_FREE=0; fi
  elif command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iTCP:80 -sTCP:LISTEN >/dev/null 2>&1; then PORT80_FREE=0; fi
  fi
  if [ "$PORT80_FREE" -eq 0 ]; then
    echo "[WARN] 80/tcp 仍被占用，ACME HTTP-01 可能无法启动。"
    echo "      请确认没有其他进程占用 80 端口（如反向代理或容器），或手动释放后重试。"
  else
    echo "[OK] 80/tcp 可用，ACME 可正常运行"
  fi
}

restore_port_80_services_if_stopped() {
  if [ "$STOPPED_NGINX" -eq 1 ]; then
    echo "[INFO] 恢复 nginx 服务..."
    systemctl start nginx 2>/dev/null || true
    STOPPED_NGINX=0
  fi
  if [ "$STOPPED_APACHE" -eq 1 ]; then
    echo "[INFO] 恢复 apache2 服务..."
    systemctl start apache2 2>/dev/null || true
    STOPPED_APACHE=0
  fi
  if [ "$STOPPED_CADDY" -eq 1 ]; then
    echo "[INFO] 恢复 caddy 服务..."
    systemctl start caddy 2>/dev/null || true
    STOPPED_CADDY=0
  fi
  if [ "$STOPPED_TRAEFIK" -eq 1 ]; then
    echo "[INFO] 恢复 traefik 服务..."
    systemctl start traefik 2>/dev/null || true
    STOPPED_TRAEFIK=0
  fi
}

# 预申请证书：优先使用 acme.sh 的 standalone 模式在 80/tcp 上申请证书
# 成功后将证书链接/复制到 /acme/shared 并设置 USE_EXISTING_CERT=1
try_issue_cert_preflight() {
  # 允许通过环境变量禁用预申请
  if [ "${DISABLE_PREFLIGHT_ACME:-0}" -eq 1 ]; then
    echo "[INFO] 已禁用预申请证书逻辑（DISABLE_PREFLIGHT_ACME=1）"
    return 1
  fi

  local domain="${SWITCHED_DOMAIN:-$HY2_DOMAIN}"
  local acme_bin=""

  # 若未设置域名，则无法进行 ACME 预申请
  if [ -z "$domain" ]; then
    echo "[ERROR] 未设置 HY2_DOMAIN，且已移除动态域名服务；无法进行 ACME 预申请。"
echo "       请设置 HY2_DOMAIN 或设置 DISABLE_SELF_SIGNED=0 使用自签 + 指纹。"
    return 1
  fi

  # 查找 acme.sh
  if command -v acme.sh >/dev/null 2>&1; then
    acme_bin="$(command -v acme.sh)"
  elif [ -x "/root/.acme.sh/acme.sh" ]; then
    acme_bin="/root/.acme.sh/acme.sh"
  else
    echo "[INFO] 未发现 acme.sh，尝试安装（仅本机，可能耗时 5-15s）"
    # 官方安装脚本（如设置 ACME_EMAIL 则会注册账户）
    if command -v curl >/dev/null 2>&1; then
      if [ -n "${ACME_EMAIL:-}" ]; then
        curl -fsSL https://get.acme.sh | sh -s email="${ACME_EMAIL}" >/dev/null 2>&1 || true
      else
        curl -fsSL https://get.acme.sh | sh >/dev/null 2>&1 || true
      fi
    elif command -v wget >/dev/null 2>&1; then
      if [ -n "${ACME_EMAIL:-}" ]; then
        wget -qO- https://get.acme.sh | sh -s email="${ACME_EMAIL}" >/dev/null 2>&1 || true
      else
        wget -qO- https://get.acme.sh | sh >/dev/null 2>&1 || true
      fi
    fi
    if [ -x "/root/.acme.sh/acme.sh" ]; then
      acme_bin="/root/.acme.sh/acme.sh"
    fi
  fi

  if [ -z "$acme_bin" ]; then
    echo "[WARN] 未能准备 acme.sh，跳过预申请"
    return 1
  fi

  # 设置默认 CA（支持 ACME_SERVER=letsencrypt|zerossl|buypass 等）
  "$acme_bin" --set-default-ca --server "${ACME_SERVER:-letsencrypt}" >/dev/null 2>&1 || true
  # 可选注册账户（letsencrypt 不强制 email，zerossl 需要）
  if [ -n "${ACME_EMAIL:-}" ]; then
    "$acme_bin" --register-account -m "${ACME_EMAIL}" --server "${ACME_SERVER:-letsencrypt}" >/dev/null 2>&1 || true
  fi

  echo "[INFO] 预申请证书（standalone/http-01）：$domain"
  # acme.sh standalone 需要 socat；自动安装以避免 "Please install socat tools first"
  if ! command -v socat >/dev/null 2>&1; then
    echo "[INFO] 检测到缺少 socat，开始安装..."
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y socat >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
      yum install -y socat >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y socat >/dev/null 2>&1 || true
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache socat >/dev/null 2>&1 || true
    elif command -v zypper >/dev/null 2>&1; then
      zypper install -y socat >/dev/null 2>&1 || true
    elif command -v pacman >/dev/null 2>&1; then
      pacman -Sy --noconfirm socat >/dev/null 2>&1 || true
    fi
    if command -v socat >/dev/null 2>&1; then
      echo "[OK] socat 安装成功"
    else
      echo "[WARN] 无法安装 socat，预申请可能失败"
    fi
  fi
  # acme.sh 会自行占用 80/tcp；确保前面已释放 80
  # 可选启用暂存环境以避开生产速率限制：ACME_STAGING=1
  local issue_args=(--issue --standalone -d "$domain" --force)
  if [ "${ACME_STAGING:-0}" -eq 1 ]; then
    issue_args+=(--staging)
    echo "[INFO] 使用 Let’s Encrypt 暂存环境进行预申请（不受生产速率限制，证书不可信）"
  fi
  local acme_output
  if ! acme_output=$("$acme_bin" "${issue_args[@]}" 2>&1); then
    if echo "$acme_output" | grep -E -iq "(rateLimited|too many certificates\s*\(5\)\s*already issued for this exact set of identifiers)"; then
echo "[WARN] 预申请命中速率限制。已移除动态域名切换；建议设置 ACME_SERVER=zerossl 或 buypass，或稍后重试，或设置 DISABLE_SELF_SIGNED=0 使用自签。"
    else
      echo "[WARN] acme.sh 预申请失败"
    fi
    return 1
  fi

  # 安装/链接证书到共享目录
  local base="$HOME/.acme.sh/$domain"
  local full="$base/fullchain.cer"
  local key="$base/$domain.key"
  if [ ! -f "$full" ] || [ ! -f "$key" ]; then
    echo "[WARN] 未找到预申请产出的证书文件"
    return 1
  fi

  mkdir -p /acme/shared
  ln -sf "$full" /acme/shared/fullchain.pem 2>/dev/null || cp -f "$full" /acme/shared/fullchain.pem
  ln -sf "$key" /acme/shared/privkey.pem 2>/dev/null || cp -f "$key" /acme/shared/privkey.pem
  USE_EXISTING_CERT=1
  USE_CERT_PATH="/acme/shared/fullchain.pem"
  USE_KEY_PATH="/acme/shared/privkey.pem"
  CERT_ORIG_PATH="$full"
  KEY_ORIG_PATH="$key"
  echo "[OK] 预申请成功，证书已链接到 /acme/shared，将使用 TLS 配置"
  echo "[OK] 抓取证书源路径：cert=$CERT_ORIG_PATH key=$KEY_ORIG_PATH"
  return 0
}

# ---- helper: 在 ACME 成功后尝试从常见路径导入主服务证书 ----
try_import_main_cert_shared() {
  # 仅在当前未检测到 /acme 证书时尝试导入
  if [ "$USE_EXISTING_CERT" -eq 1 ]; then
    return 0
  fi

  # 支持域名切换后的匹配
  local domain="${SWITCHED_DOMAIN:-$HY2_DOMAIN}"
  # 常见缓存目录（包括脚本配置的 /acme/autocert）
  local candidates=(
    "/acme/autocert"
    "/root/.cache/autocert"
    "/root/.acme.sh"
    "/var/lib/hysteria"
    "/etc/hysteria"
    "/var/cache/hysteria"
    "/etc/letsencrypt/live"
    "/etc/ssl"
    "/etc/nginx"
    "/usr/local/etc/nginx"
    "/etc/apache2"
    "/etc/httpd"
    "/etc/pki/tls"
    "/etc/caddy"
    "/var/lib/caddy"
    "/etc/traefik"
    "/var/lib/traefik"
  )

  # 证书域名/SAN 校验 + 私钥匹配校验
  verify_cert_key_pair() {
    local cert="$1" key="$2" dom="$3"
    if ! command -v openssl >/dev/null 2>&1; then
      # 无 openssl 时不做严格校验，直接接受
      return 0
    fi

    # 证书未来 24h 不过期
    if ! openssl x509 -checkend 86400 -noout -in "$cert" >/dev/null 2>&1; then
      return 1
    fi

    # 域名匹配（SubjectAltName 或 CN）
    cert_domain_matches() {
      local c="$1" d="$2"
      local san_entries=()
      mapfile -t san_entries < <(openssl x509 -noout -ext subjectAltName -in "$c" 2>/dev/null | grep -o -E 'DNS:[^,]+' | sed 's/^DNS://')
      # 直接匹配
      for e in "${san_entries[@]}"; do
        [ "$e" = "$d" ] && return 0
      done
      # 通配符匹配（*.example.com 匹配 foo.example.com）
      for e in "${san_entries[@]}"; do
        case "$e" in
          \*.*)
            local suffix="${e#*.}"
            case "$d" in
              *."$suffix") return 0;;
            esac
            ;;
        esac
      done
      # 退化为 CN 匹配
      local cn
      cn="$(openssl x509 -noout -subject -in "$c" 2>/dev/null | grep -o -E 'CN=[^/,]+' | head -n1 | sed 's/^CN=//')"
      [ -n "$cn" ] && [ "$cn" = "$d" ]
    }
    cert_domain_matches "$cert" "$dom" || return 1

    # 证书与私钥是否匹配：比较公钥哈希（兼容 RSA/ECDSA）
    local cert_pub_hash key_pub_hash
    cert_pub_hash="$(openssl x509 -noout -pubkey -in "$cert" 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')"
    key_pub_hash="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')"
    [ -n "$cert_pub_hash" ] && [ -n "$key_pub_hash" ] && [ "$cert_pub_hash" = "$key_pub_hash" ]
  }

  # 在 /acme/shared 放置证书与私钥：优先使用符号链接以跟随轮转；必要时回退复制
  link_or_copy() {
    local src="$1" dst="$2"
    ln -sf "$src" "$dst" 2>/dev/null || cp -f "$src" "$dst" 2>/dev/null || cat "$src" >"$dst"
  }

  place_cert_and_key() {
    local cert_src="$1" key_src="$2"
    mkdir -p /acme/shared
    local cert_dir
    cert_dir="$(dirname "$cert_src")"
    if [ -f "$cert_dir/fullchain.pem" ]; then
      link_or_copy "$cert_dir/fullchain.pem" /acme/shared/fullchain.pem
      echo "[INFO] 使用符号链接/复制指向源 fullchain.pem，以跟随上游轮转"
      CERT_ORIG_PATH="$cert_dir/fullchain.pem"
    else
      # 若发现 chain.pem，但无 fullchain，尝试合并；否则直接链接/复制源证书
      if [ -f "$cert_dir/chain.pem" ]; then
        if cat "$cert_src" "$cert_dir/chain.pem" > /acme/shared/fullchain.pem 2>/dev/null; then
          echo "[INFO] 源路径无 fullchain.pem，已合并 cert+chain 到 /acme/shared/fullchain.pem（轮转后需重跑脚本以更新）"
          CERT_ORIG_PATH="$cert_src"
          CERT_CHAIN_ORIG_PATH="$cert_dir/chain.pem"
        else
          link_or_copy "$cert_src" /acme/shared/fullchain.pem
          echo "[INFO] 已链接/复制源证书到 /acme/shared/fullchain.pem"
          CERT_ORIG_PATH="$cert_src"
        fi
      else
        link_or_copy "$cert_src" /acme/shared/fullchain.pem
        echo "[INFO] 已链接/复制源证书到 /acme/shared/fullchain.pem"
        CERT_ORIG_PATH="$cert_src"
      fi
    fi
    link_or_copy "$key_src" /acme/shared/privkey.pem
    KEY_ORIG_PATH="$key_src"
    USE_EXISTING_CERT=1
    USE_CERT_PATH="/acme/shared/fullchain.pem"
    USE_KEY_PATH="/acme/shared/privkey.pem"
    echo "[OK] 抓取证书源路径：cert=${CERT_ORIG_PATH:-unknown} key=${KEY_ORIG_PATH:-unknown}"
  }

  local found_cert="" found_key=""
  for d in "${candidates[@]}"; do
    [ -d "$d" ] || continue
    # 在候选目录下尽可能多地找出证书/私钥候选
    mapfile -t certs < <(find "$d" -maxdepth 6 \( -type f -o -type l \) \( \
      -name "*fullchain*.pem" -o -name "*${domain}*.crt" -o -name "*${domain}*.cer" -o -name "*cert*.pem" -o -name "*.crt" -o -name "*.cer" \
    \) 2>/dev/null)
    mapfile -t keys < <(find "$d" -maxdepth 6 \( -type f -o -type l \) \( \
      -name "*privkey*.pem" -o -name "*${domain}*.key" -o -name "*key*.pem" -o -name "*.key" \
    \) 2>/dev/null)

    # 优先同目录匹配；否则尝试跨目录匹配
    for c in "${certs[@]}"; do
      # 优先找同目录下的密钥
      local base_dir
      base_dir="$(dirname "$c")"
      local k_same
      k_same="$(find "$base_dir" -maxdepth 1 \( -type f -o -type l \) \( -name "*privkey*.pem" -o -name "*${domain}*.key" -o -name "*key*.pem" -o -name "*.key" \) 2>/dev/null | head -n1)"
      if [ -n "$k_same" ] && verify_cert_key_pair "$c" "$k_same" "$domain"; then
        found_cert="$c"; found_key="$k_same"; break
      fi
      # 退化为跨目录匹配
      for k in "${keys[@]}"; do
        if verify_cert_key_pair "$c" "$k" "$domain"; then
          found_cert="$c"; found_key="$k"; break
        fi
      done
      [ -n "$found_cert" ] && break
    done

    if [ -n "$found_cert" ] && [ -n "$found_key" ]; then
      place_cert_and_key "$found_cert" "$found_key"
      echo "[OK] 已从主服务导入证书到 /acme/shared（校验通过），用于多端口实例"
      return 0
    fi
  done

  # 额外扫描常见家目录 ACME 路径（若存在）
  for d in /home/*/.acme.sh /home/*/.lego /home/*/.certbot /home/*/letsencrypt/live /var/www/cert; do
    [ -d "$d" ] || continue
    mapfile -t certs < <(find "$d" -maxdepth 4 \( -type f -o -type l \) \( -name "*fullchain*.pem" -o -name "*${domain}*.crt" -o -name "*${domain}*.cer" -o -name "*cert*.pem" -o -name "*.crt" -o -name "*.cer" \) 2>/dev/null)
    mapfile -t keys < <(find "$d" -maxdepth 4 \( -type f -o -type l \) \( -name "*privkey*.pem" -o -name "*${domain}*.key" -o -name "*key*.pem" -o -name "*.key" \) 2>/dev/null)
    for c in "${certs[@]}"; do
      local base_dir k_same
      base_dir="$(dirname "$c")";
      k_same="$(find "$base_dir" -maxdepth 1 \( -type f -o -type l \) \( -name "*privkey*.pem" -o -name "*${domain}*.key" -o -name "*key*.pem" -o -name "*.key" \) 2>/dev/null | head -n1)"
      if [ -n "$k_same" ] && verify_cert_key_pair "$c" "$k_same" "$domain"; then
        found_cert="$c"; found_key="$k_same"; break
      fi
      for k in "${keys[@]}"; do
        if verify_cert_key_pair "$c" "$k" "$domain"; then
          found_cert="$c"; found_key="$k"; break
        fi
      done
      [ -n "$found_cert" ] && break
    done
    if [ -n "$found_cert" ] && [ -n "$found_key" ]; then
      place_cert_and_key "$found_cert" "$found_key"
      echo "[OK] 已从家目录 ACME 路径导入证书到 /acme/shared（校验通过）"
      return 0
    fi
  done

  # 从 Nginx/Apache 配置提取证书路径并导入（若找到）
  try_import_from_nginx_configs "$domain" && return 0 || true
  try_import_from_apache_configs "$domain" && return 0 || true
  try_import_from_caddy_storage "$domain" && return 0 || true
  try_import_from_traefik_acme_json "$domain" && return 0 || true

  echo "[WARN] 未能定位主服务证书缓存文件，仍将仅运行主端口。若需多端口，请将证书放入 /acme/<dir>/fullchain.pem 与 privkey.pem。"
  return 1
}

# ---- helper: 从 Nginx 配置导入证书 ----
try_import_from_nginx_configs() {
  local dom="$1"
  local cfg_dirs=(
    "/etc/nginx" "/usr/local/etc/nginx"
  )
  for cd in "${cfg_dirs[@]}"; do
    [ -d "$cd" ] || continue
    # 提取所有证书/密钥路径
    mapfile -t cert_paths < <(grep -R -E "^\s*ssl_certificate\s+" "$cd" 2>/dev/null | awk '{print $2}' | sed 's/;\s*$//' | sort -u)
    mapfile -t key_paths < <(grep -R -E "^\s*ssl_certificate_key\s+" "$cd" 2>/dev/null | awk '{print $2}' | sed 's/;\s*$//' | sort -u)
    for c in "${cert_paths[@]}"; do
      [ -f "$c" ] || continue
      local k
      # 同目录优先
      k="$(dirname "$c")"; k="$k/privkey.pem"; [ -f "$k" ] || k=""
      if [ -z "$k" ]; then
        for kp in "${key_paths[@]}"; do
          [ -f "$kp" ] && { k="$kp"; break; }
        done
      fi
      [ -n "$k" ] || continue
      if verify_cert_key_pair "$c" "$k" "$dom"; then
        place_cert_and_key "$c" "$k"
        echo "[OK] 已从 Nginx 配置导入证书（优先链接 fullchain 以跟随轮转）"
        return 0
      fi
    done
  done
  return 1
}

# ---- helper: 从 Apache 配置导入证书 ----
try_import_from_apache_configs() {
  local dom="$1"
  local cfg_dirs=("/etc/apache2" "/etc/httpd")
  for cd in "${cfg_dirs[@]}"; do
    [ -d "$cd" ] || continue
    mapfile -t cert_paths < <(grep -R -E "^\s*SSLCertificateFile\s+" "$cd" 2>/dev/null | awk '{print $2}' | sort -u)
    mapfile -t key_paths < <(grep -R -E "^\s*SSLCertificateKeyFile\s+" "$cd" 2>/dev/null | awk '{print $2}' | sort -u)
    for c in "${cert_paths[@]}"; do
      [ -f "$c" ] || continue
      local k=""
      for kp in "${key_paths[@]}"; do
        [ -f "$kp" ] && { k="$kp"; break; }
      done
      [ -n "$k" ] || continue
      if verify_cert_key_pair "$c" "$k" "$dom"; then
        place_cert_and_key "$c" "$k"
        echo "[OK] 已从 Apache 配置导入证书（优先链接 fullchain 以跟随轮转）"
        return 0
      fi
    done
  done
  return 1
}

# ---- helper: 从 Caddy 存储导入证书 ----
try_import_from_caddy_storage() {
  local dom="$1"; local base="/var/lib/caddy/.local/share/caddy/certificates"
  [ -d "$base" ] || return 1
  mapfile -t certs < <(find "$base" -maxdepth 6 \( -type f -o -type l \) -name "*.crt" 2>/dev/null)
  for c in "${certs[@]}"; do
    local dname
    dname="$(basename "$c" .crt)"
    # 尝试按同名 key
    local k="${c%.crt}.key"
    [ -f "$k" ] || continue
    if verify_cert_key_pair "$c" "$k" "$dom"; then
      place_cert_and_key "$c" "$k"
      echo "[OK] 已从 Caddy 存储导入证书（优先链接 fullchain 以跟随轮转）"
      return 0
    fi
  done
  return 1
}

# ---- helper: 从 Traefik acme.json 导入证书 ----
try_import_from_traefik_acme_json() {
  local dom="$1"; local json="/var/lib/traefik/acme.json"
  [ -f "$json" ] || return 1
  if ! command -v python3 >/dev/null 2>&1; then return 1; fi
  python3 - "$json" "$dom" <<'PY' && exit 0 || exit 1
import sys, json, base64
path = sys.argv[1]
dom = sys.argv[2]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
def iter_certs(d):
    # Traefik 不同版本结构不同，尽量兼容
    stores = []
    for k in ('Certificates', 'Store', 'http', 'tls', 'store', 'acme'): 
        v = d.get(k)
        if isinstance(v, dict): d = v
    # 最常见结构
    for provider in d.values():
        if isinstance(provider, dict):
            for entry in provider.get('Certificates', []):
                yield entry
            # 可能的备用键
            for entry in provider.get('Store', {}).get('Certificates', []):
                yield entry
itered = list(iter_certs(data))
match = None
for e in itered:
    doms = []
    if 'domain' in e:
        if isinstance(e['domain'], dict):
            doms.append(e['domain'].get('main'))
            doms += e['domain'].get('sans', []) or []
        else:
            doms.append(e['domain'])
    for d in doms:
        if d == dom or (isinstance(d, str) and d.startswith('*.') and dom.endswith(d[2:])):
            match = e; break
    if match: break
if not match:
    sys.exit(1)
cert_b64 = match.get('certificate')
key_b64 = match.get('key')
if not cert_b64 or not key_b64:
    sys.exit(1)
cert = base64.b64decode(cert_b64)
key = base64.b64decode(key_b64)
open('/acme/shared/fullchain.pem', 'wb').write(cert)
open('/acme/shared/privkey.pem', 'wb').write(key)
print('[OK] 已从 Traefik acme.json 导入证书到 /acme/shared')
PY
  if [ $? -eq 0 ]; then
    USE_EXISTING_CERT=1
    USE_CERT_PATH="/acme/shared/fullchain.pem"
    USE_KEY_PATH="/acme/shared/privkey.pem"
    echo "[OK] 已从 Traefik 导入证书到 /acme/shared（内容复制；若轮转需重跑脚本）"
    return 0
  fi
  return 1
}

# ---- helper: 使用 ACME 缓存目录启动额外端口（导入失败的回退方案） ----
start_additional_instances_with_acme_cache() {
  [ -n "${HY2_PORTS:-}" ] || return 0
  ensure_systemd_template
  IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
  for pt in "${ports_all[@]}"; do
    [ "$pt" = "$HY2_PORT" ] && continue
    # 使用 ACME dir 缓存（不会重复发起挑战，直接读取已缓存证书）
    write_hysteria_config_for_port "$pt" "${PASS_MAP[$pt]}" "${OBFS_MAP[$pt]}" "0"
    start_hysteria_instance "$pt"
  done
  ensure_udp_ports_open "$PORT_LIST_CSV"
}

# ===========================
# helper: 定义定时维护任务（每天清缓存+硬重启）
# ===========================
setup_auto_reboot_cron() {
  # 可通过 ENABLE_AUTO_REBOOT_CACHE=0 关闭
  if [ "${ENABLE_AUTO_REBOOT_CACHE:-1}" != "1" ]; then
    echo "[INFO] 自动维护任务已禁用（ENABLE_AUTO_REBOOT_CACHE=0）"
    return 0
  fi

  # 解析命令绝对路径，确保可用
  local SHUTDOWN_BIN=""
  if [ -x /sbin/shutdown ]; then
    SHUTDOWN_BIN="/sbin/shutdown"
  elif [ -x /usr/sbin/shutdown ]; then
    SHUTDOWN_BIN="/usr/sbin/shutdown"
  elif command -v shutdown >/dev/null 2>&1; then
    SHUTDOWN_BIN="$(command -v shutdown)"
  else
    echo "[ERROR] 未找到 shutdown 命令，无法设置硬重启任务"
    return 1
  fi

  local SYNC_BIN=""
  if [ -x /usr/bin/sync ]; then
    SYNC_BIN="/usr/bin/sync"
  elif command -v sync >/dev/null 2>&1; then
    SYNC_BIN="$(command -v sync)"
  else
    echo "[ERROR] 未找到 sync 命令，无法设置缓存清理任务"
    return 1
  fi

  local DROP_CACHES="/proc/sys/vm/drop_caches"
  if [ ! -e "$DROP_CACHES" ]; then
    echo "[WARN] 未找到 $DROP_CACHES，内存缓存清理可能无法执行"
  elif [ ! -w "$DROP_CACHES" ]; then
    echo "[WARN] 无法写入 $DROP_CACHES，请确保以 root 运行"
  fi

  local CRON_LINE="0 3 * * * ${SYNC_BIN} && echo 3 > ${DROP_CACHES} && ${SHUTDOWN_BIN} -r now"

  # 确保 cron 服务可用
  if ! command -v crontab >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      echo "[INFO] 未检测到 crontab，尝试安装 cron..."
      DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y cron >/dev/null 2>&1 || true
    else
      echo "[WARN] 未找到 crontab 命令且无法自动安装 cron。请手动安装后重试。"
    fi
  fi

  # 尝试启动并设置 cron 服务
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now cron >/dev/null 2>&1 || true
    if ! systemctl is-active --quiet cron; then
      echo "[WARN] cron 服务未处于 active 状态，请检查：systemctl status cron"
    fi
  else
    service cron start >/dev/null 2>&1 || true
  fi

  if command -v crontab >/dev/null 2>&1; then
    # 仅在不存在时添加，保证幂等
    local EXISTING
    EXISTING="$(crontab -l 2>/dev/null || true)"
    if ! printf "%s\n" "$EXISTING" | grep -Fq "$CRON_LINE"; then
      local TMP_CRON
      TMP_CRON="$(mktemp)"
      printf "%s\n" "$EXISTING" >"$TMP_CRON"
      printf "%s\n" "$CRON_LINE" >>"$TMP_CRON"
      crontab "$TMP_CRON"
      rm -f "$TMP_CRON"
      echo "[OK] 已添加 root 定时任务：每天 03:00 清缓存并重启"
    else
      echo "[INFO] root 定时任务已存在，跳过添加"
    fi

    # 就绪确认：确认已写入 crontab
    if crontab -l 2>/dev/null | grep -Fq "$CRON_LINE"; then
      echo "[OK] 硬重启就绪：crontab 已写入，命令路径: ${SYNC_BIN}, ${SHUTDOWN_BIN}"
    fi
  fi
}

# ===========================
# 模式选择：1 全新安装；2 仅添加维护任务
# 可用环境变量 SCRIPT_MODE=1/2 跳过交互
# ===========================
SCRIPT_MODE="${SCRIPT_MODE:-}"
if [ -z "$SCRIPT_MODE" ]; then
  if [ -t 0 ]; then
    read -r -p "请选择模式: 1) 全新安装  2) 仅添加每天自动清缓存+硬重启 [默认1]: " SCRIPT_MODE || true
  else
    SCRIPT_MODE="1"
  fi
fi

case "${SCRIPT_MODE}" in
  2)
    echo "[INFO] 选择模式 2：仅添加每天自动清缓存+硬重启"
    ENABLE_AUTO_REBOOT_CACHE="${ENABLE_AUTO_REBOOT_CACHE:-1}"
    setup_auto_reboot_cron
    echo "[OK] 维护任务已添加，脚本结束。"
    exit 0
    ;;
  1|"")
    echo "[INFO] 选择模式 1：全新安装"
    ;;
  *)
    echo "[WARN] 无效选择（${SCRIPT_MODE}），默认使用模式 1：全新安装"
    ;;
esac

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
# 2) 域名处理（可选）
# ===========================
if [ "${DISABLE_SELF_SIGNED:-1}" -eq 0 ]; then
  HY2_DOMAIN=""
  echo "[INFO] 自签 + 指纹模式启用：不使用域名/SNI"
else
  if [ -n "${HY2_DOMAIN:-}" ]; then
    echo "[OK] 使用自定义域名：${HY2_DOMAIN}"
    # 可选校验解析是否指向本机 IP（不强制）
    resolved_ip="$(getent ahostsv4 "$HY2_DOMAIN" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
    if [ -z "$resolved_ip" ] && command -v nslookup >/dev/null 2>&1; then
      resolved_ip="$(nslookup "$HY2_DOMAIN" 2>/dev/null | awk '/^Address: / { print $2 }' | head -n1 || true)"
    fi
    if [ -z "$resolved_ip" ] && command -v dig >/dev/null 2>&1; then
      resolved_ip="$(dig +short "$HY2_DOMAIN" A 2>/dev/null | head -n1 || true)"
    fi
    if [ -n "$resolved_ip" ] && [ "$resolved_ip" != "$SELECTED_IP" ]; then
      echo "[WARN] 域名解析到 ${resolved_ip}，与本机 ${SELECTED_IP} 不一致；ACME 可能失败"
    fi
  else
    echo "[ERROR] 未设置 HY2_DOMAIN，且已移除动态域名服务。"
    echo "       如需使用 ACME，请设置 HY2_DOMAIN 指向本机；或设置 DISABLE_SELF_SIGNED=0 使用自签 + 指纹。"
  fi
fi

# ===========================
# 3) 安装 hysteria 二进制（若不存在）
# ===========================
if ! command -v hysteria >/dev/null 2>&1; then
  echo "[*] 安装 hysteria ..."
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) asset="hysteria-linux-amd64" ;;
    aarch64|arm64) asset="hysteria-linux-arm64" ;;
    armv7l|armv7|armhf) asset="hysteria-linux-armv7" ;;
    i386|i486|i586|i686) asset="hysteria-linux-386" ;;
    ppc64le) asset="hysteria-linux-ppc64le" ;;
    riscv64) asset="hysteria-linux-riscv64" ;;
    s390x) asset="hysteria-linux-s390x" ;;
    *) asset="hysteria-linux-amd64" ;;
  esac
  # 允许手动覆盖下载资产名（例如 HYST_ASSET_OVERRIDE=hysteria-linux-armv7）
  if [ -n "${HYST_ASSET_OVERRIDE:-}" ]; then
    asset="${HYST_ASSET_OVERRIDE}"
  fi
  mkdir -p /usr/local/bin
  url_default="https://github.com/apernet/hysteria/releases/latest/download/${asset}"
  # 可通过环境变量指定镜像基地址（例如 ghproxy）：HYST_DOWNLOAD_BASE=https://ghproxy.com/https://github.com/apernet/hysteria/releases/latest/download
  # 若未指定则使用默认 + 常见镜像回退
  urls=()
  if [ -n "${HYST_DOWNLOAD_BASE:-}" ]; then
    urls+=("${HYST_DOWNLOAD_BASE%/}/${asset}")
  fi
  urls+=(
    "$url_default"
    "https://ghproxy.com/https://github.com/apernet/hysteria/releases/latest/download/${asset}"
    "https://download.fastgit.org/apernet/hysteria/releases/latest/download/${asset}"
  )

  # 安装下载工具（如缺失）
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y >/dev/null 2>&1 || true
      apt-get install -y curl >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
      yum install -y curl >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y curl >/dev/null 2>&1 || true
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache curl >/dev/null 2>&1 || true
    fi
  fi

  download_ok=0
  for u in "${urls[@]}"; do
    if command -v curl >/dev/null 2>&1; then
      echo "[*] 尝试下载: $u"
      curl -fL --connect-timeout 10 -m 60 "$u" -o /usr/local/bin/hysteria && download_ok=1 && break || true
    fi
    if [ "$download_ok" -ne 1 ] && command -v wget >/dev/null 2>&1; then
      echo "[*] 尝试下载: $u"
      wget -O /usr/local/bin/hysteria "$u" && download_ok=1 && break || true
    fi
  done
  if [ "$download_ok" -ne 1 ]; then
    echo "[ERROR] 无法下载 hysteria 二进制。请检查网络，或设置 HYST_DOWNLOAD_BASE 为镜像地址。"
  fi
  chmod +x /usr/local/bin/hysteria
  verify_ok=0
  # 兼容不同版本的版本打印命令
  if /usr/local/bin/hysteria -v >/dev/null 2>&1; then verify_ok=1; fi
  if [ "$verify_ok" -ne 1 ] && /usr/local/bin/hysteria --version >/dev/null 2>&1; then verify_ok=1; fi
  if [ "$verify_ok" -ne 1 ] && /usr/local/bin/hysteria version >/dev/null 2>&1; then verify_ok=1; fi
  if [ "$verify_ok" -eq 1 ]; then
    echo "[OK] hysteria 安装完成"
  else
    # 输出诊断信息帮助定位问题（架构/文件类型/可执行权限）
    echo "[ERROR] hysteria 二进制安装失败：无法正常执行版本命令"
    echo "       uname -m: $arch"
    if command -v file >/dev/null 2>&1; then
      echo "       file /usr/local/bin/hysteria: $(file /usr/local/bin/hysteria 2>/dev/null)"
    fi
    if [ ! -x /usr/local/bin/hysteria ]; then
      echo "       提示：文件不可执行（-x 缺失），尝试 chmod +x /usr/local/bin/hysteria"
    fi
    echo "       若为架构不匹配，请设置 HYST_ASSET_OVERRIDE 为合适的资产名后重试。"
    echo "       示例：HYST_ASSET_OVERRIDE=hysteria-linux-armv7 或 hysteria-linux-386"
  fi
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

# 若未提供 HY2_PORTS，则尝试交互式生成端口列表
maybe_init_ports_from_input

# 解析端口列表并生成每端口凭据
PORT_LIST_CSV="$(parse_port_list)"
gen_credentials_for_ports "$PORT_LIST_CSV"

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

# 如设置 DISABLE_SELF_SIGNED=0，则跳过 ACME/导入并强制生成自签证书（自签+指纹）
if [ "${DISABLE_SELF_SIGNED:-1}" -eq 0 ]; then
  echo "[INFO] 已启用自签 + 指纹模式：跳过 ACME 与现有证书，使用自签证书"
  USE_EXISTING_CERT=0
  USE_CERT_PATH=""
  USE_KEY_PATH=""
  generate_self_signed_cert
fi

if [ "$USE_EXISTING_CERT" -eq 0 ]; then
  echo "[INFO] /acme 下未找到证书，先尝试预申请（standalone/http-01）..."
  # 提前检查/释放 80/tcp，预申请将占用该端口
  ensure_port_80_available
  if try_issue_cert_preflight; then
    echo "[OK] 预申请完成，已将证书放置到 /acme/shared"
  else
    echo "[INFO] 预申请失败，尝试从主服务缓存自动导入证书..."
    if try_import_main_cert_shared; then
      echo "[OK] 已自动导入主证书到 /acme/shared，将用于多端口实例"
    else
      echo "[INFO] 未能导入缓存，后续将使用内置 ACME（需 80/tcp 可达）"
    fi
  fi
fi

# ===========================
# 6) 写 hysteria 配置（使用已找到的证书或 ACME 配置）
# ===========================
mkdir -p /etc/hysteria
if [ "$USE_EXISTING_CERT" -eq 1 ]; then
  write_hysteria_main_config 1
  echo "[OK] 已写入 hysteria 配置（使用 /acme 证书）"
  start_additional_instances_with_tls
else
  # 默认禁用自签证书回退；如需启用可设置 DISABLE_SELF_SIGNED=0
  DISABLE_SELF_SIGNED=${DISABLE_SELF_SIGNED:-1}
  if [ "$PORT80_FREE" -eq 1 ]; then
    write_hysteria_main_config 0
    echo "[OK] 已写入 hysteria 配置（使用 ACME HTTP-01）"
  else
    if [ "$DISABLE_SELF_SIGNED" -eq 1 ]; then
      echo "[ERROR] 80/tcp 不可用且无现有证书，已禁用自签证书回退。"
      echo "       请释放 80 端口或提供 /acme 证书后再运行。"
      # 仍写入 ACME 配置，便于释放 80 后自动申请
      write_hysteria_main_config 0
      echo "[INFO] 已写入 ACME 配置，但启动可能失败，需释放 80/tcp。"
    else
      echo "[WARN] 80/tcp 不可用且无现有证书，启用自签回退以便临时启动"
      generate_self_signed_cert
      write_hysteria_main_config 1
      SELF_SIGNED_USED=1
      echo "[OK] 已写入 hysteria 配置（使用自签证书）"
    fi
  fi
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
if [ "$USE_EXISTING_CERT" -eq 0 ]; then
  # 申请 ACME 前确保 80/tcp 可用并已放行
  ensure_port_80_available
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now hysteria-server || true
  sleep 2
  systemctl restart hysteria-server || true
  if ! systemctl is-active --quiet hysteria-server; then
    echo "[WARN] hysteria-server 未处于 active 状态，输出最近日志以诊断："
    journalctl -u hysteria-server -n 80 --no-pager 2>/dev/null || true
    start_main_service_direct
  fi
else
  start_main_service_direct
fi

# 启动额外端口实例（需要 /acme 证书）
if [ "$USE_EXISTING_CERT" -eq 1 ] && [ -n "${HY2_PORTS:-}" ]; then
  ensure_systemd_template
  IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
  for pt in "${ports_all[@]}"; do
    if [ "$pt" != "$HY2_PORT" ]; then
      start_hysteria_instance "$pt"
    fi
  done
  ensure_udp_ports_open "$PORT_LIST_CSV"
fi


# ===========================
# 8) 如果没有现有证书则等待 ACME 产生日志（最多 60 秒）
# ===========================
if [ "$USE_EXISTING_CERT" -eq 0 ]; then
  echo "[*] 等待 hysteria ACME 证书申请完成（最多 60 秒）..."
  TRIES=0
  ACME_OK=0
  RATE_LIMITED=0
  
  while [ $TRIES -lt 12 ]; do
    # 检查证书申请成功
    if journalctl -u hysteria-server --no-pager -n 200 | grep -E -iq "(certificate obtained successfully|acme_client.*authorization finalized|acme.*valid)"; then
      ACME_OK=1
      break
    fi
    
    # 检查 HTTP 429 速率限制错误
    if journalctl -u hysteria-server --no-pager -n 200 | grep -E -iq "(429|rate.?limit|too.?many.?requests|rateLimited)"; then
      RATE_LIMITED=1
  echo "[WARN] 检测到 HTTP 429 速率限制错误。"
      break
    fi
    
    sleep 5
    TRIES=$((TRIES+1))
  done

  # 处理速率限制：不再切换动态域名，给出建议
  if [ "$RATE_LIMITED" -eq 1 ]; then
    echo "[WARN] 检测到 ACME 速率限制（429）。已移除动态域名切换逻辑。"
echo "       建议：设置 ACME_SERVER=zerossl 或 buypass，或稍后重试；如无需公信任，设置 DISABLE_SELF_SIGNED=0 使用自签 + 指纹。"
  fi

  if [ "$ACME_OK" -ne 1 ] && [ "$RATE_LIMITED" -eq 0 ]; then
    echo "[WARN] 未检测到 ACME 成功日志，但可能证书已申请成功。检查日志详情："
    journalctl -u hysteria-server -n 50 --no-pager | grep -E -i "(acme|certificate|tls-alpn|http-01|challenge|429|rate.?limit)" || true
    echo "[INFO] 继续执行，证书可能已成功获取"
  elif [ "$ACME_OK" -eq 1 ]; then
    echo "[OK] ACME 证书申请成功检测到"
    # 证书申请成功后，优先导入主证书并将主端口切换为 TLS
    if try_import_main_cert_shared; then
      write_hysteria_main_config 1
      systemctl restart hysteria-server || true
      echo "[OK] 主端口已切换为 TLS 证书运行"
    else
      echo "[WARN] 未能导入主证书缓存；主端口继续使用 ACME 配置运行"
    fi

    # 若启用多端口，仅在导入主证书成功后启动多实例（避免 ACME 并发占用 80/tcp）
    if [ -n "${HY2_PORTS:-}" ]; then
      if [ "$USE_EXISTING_CERT" -eq 1 ]; then
        start_additional_instances_with_tls
      else
        echo "[WARN] ACME 成功但未找到可导入证书，尝试使用 ACME 缓存启动多端口"
        start_additional_instances_with_acme_cache
        echo "[OK] 额外端口已基于 ACME 缓存启动"
      fi
    fi
  fi
else
  echo "[OK] 使用现有 /acme 证书，跳过 ACME 等待"
fi

# 如果为申请证书暂时关闭了 80/tcp 上的服务，这里恢复
restore_port_80_services_if_stopped

# 在完成证书流程后，若未启用多端口，则至少放行主端口 UDP
if [ -z "${HY2_PORTS:-}" ]; then
  ensure_udp_ports_open "$HY2_PORT"
fi

setup_auto_reboot_cron

print_hysteria_process_info
echo "=== 监听检查（UDP/${HY2_PORT}) ==="
check_udp_listening "$HY2_PORT"
if [ -n "${HY2_PORTS:-}" ]; then
  echo "=== 监听检查（其他端口） ==="
  IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
  for pt in "${ports_all[@]}"; do
    if [ "$pt" != "$HY2_PORT" ]; then
      check_udp_listening "$pt"
    fi
  done
fi

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

INSECURE_VAL=0
# 自签 + 指纹模式下，始终保持 insecure=0 并输出 pinSHA256
if [ "${DISABLE_SELF_SIGNED:-1}" -eq 0 ] || [ "${SELF_SIGNED_USED:-0}" -eq 1 ]; then
  URI="hysteria2://${PASS_ENC}@${SELECTED_IP}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"
else
  URI="hysteria2://${PASS_ENC}@${SELECTED_IP}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=${INSECURE_VAL}&pinSHA256=${PIN_ENC}#${NAME_ENC}"
fi

echo
echo "=========== HY2 节点（URI） ==========="
echo "${URI}"
echo "======================================="
echo
if [ -n "${HY2_PORTS:-}" ]; then
  echo "=========== 其他端口（URI） ==========="
  IFS=',' read -r -a print_ports <<<"$PORT_LIST_CSV"
  for pt in "${print_ports[@]}"; do
    if [ "$pt" = "$HY2_PORT" ]; then continue; fi
    P_PASS="${PASS_MAP[$pt]}"; P_OBFS="${OBFS_MAP[$pt]}"
    P_PASS_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$P_PASS")"
    P_OBFS_ENC="$(python3 -c "import sys,urllib.parse as u; print(u.quote(sys.argv[1], safe=''))" "$P_OBFS")"
    if [ "${DISABLE_SELF_SIGNED:-1}" -eq 0 ] || [ "${SELF_SIGNED_USED:-0}" -eq 1 ]; then
      P_URI="hysteria2://${P_PASS_ENC}@${SELECTED_IP}:${pt}/?protocol=udp&obfs=salamander&obfs-password=${P_OBFS_ENC}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"
    else
      P_URI="hysteria2://${P_PASS_ENC}@${SELECTED_IP}:${pt}/?protocol=udp&obfs=salamander&obfs-password=${P_OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"
    fi
    echo "$pt -> $P_URI"
  done
  echo "======================================="
  echo
fi

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
    __SNI_LINE__

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
if [ "${DISABLE_SELF_SIGNED:-1}" -eq 0 ] || [ "${SELF_SIGNED_USED:-0}" -eq 1 ]; then
  SNI_LINE=""
else
  SNI_LINE="sni: ${HY2_DOMAIN}"
fi
SNI_ESC="$(escape_for_sed "${SNI_LINE}")"

sed -e "s@__NAME_TAG__@${NAME_ESC}@g" \
    -e "s@__SELECTED_IP__@${IP_ESC}@g" \
    -e "s@__HY2_PORT__@${PORT_ESC}@g" \
    -e "s@__HY2_PASS__@${PASS_ESC}@g" \
    -e "s@__OBFS_PASS__@${OBFS_ESC}@g" \
    -e "s@__SNI_LINE__@${SNI_ESC}@g" \
    "${TMPF}" > "${TARGET}"
rm -f "${TMPF}"

echo "[OK] Clash 订阅已写入：${TARGET}"

# 若启用多端口，为每端口生成独立订阅文件（与证书无关，仅生成文件）
if [ -n "${HY2_PORTS:-}" ]; then
  IFS=',' read -r -a clash_ports <<<"$PORT_LIST_CSV"
  for pt in "${clash_ports[@]}"; do
    [ "$pt" = "$HY2_PORT" ] && continue
    local_tmp="${CLASH_WEB_DIR}/clash_${pt}.yaml.tmp"
    local_target="${CLASH_WEB_DIR}/clash_${pt}.yaml"
    cat >"${local_tmp}" <<'EOF'
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
    __SNI_LINE__

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
    NAME_ESC2="$(escape_for_sed "${NAME_TAG}")"
    IP_ESC2="$(escape_for_sed "${SELECTED_IP}")"
    PORT_ESC2="$(escape_for_sed "${pt}")"
    PASS_ESC2="$(escape_for_sed "${PASS_MAP[$pt]}")"
    OBFS_ESC2="$(escape_for_sed "${OBFS_MAP[$pt]}")"
    if [ "${DISABLE_SELF_SIGNED:-1}" -eq 0 ] || [ "${SELF_SIGNED_USED:-0}" -eq 1 ]; then
      SNI_LINE2=""
    else
      SNI_LINE2="sni: ${HY2_DOMAIN}"
    fi
    SNI_ESC2="$(escape_for_sed "${SNI_LINE2}")"
    sed -e "s@__NAME_TAG__@${NAME_ESC2}@g" \
        -e "s@__SELECTED_IP__@${IP_ESC2}@g" \
        -e "s@__HY2_PORT__@${PORT_ESC2}@g" \
        -e "s@__HY2_PASS__@${PASS_ESC2}@g" \
        -e "s@__OBFS_PASS__@${OBFS_ESC2}@g" \
        -e "s@__SNI_LINE__@${SNI_ESC2}@g" \
        "${local_tmp}" > "${local_target}"
    rm -f "${local_tmp}"
    echo "[OK] Clash 订阅已写入：${local_target}"
  done
fi

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
    # 额外路由：提供每端口订阅文件 /clash_<port>.yaml
    location ~ ^/clash_[0-9]+\.yaml$ {
        default_type application/x-yaml;
        try_files \$uri =404;
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
if [ -n "${HY2_PORTS:-}" ]; then
  IFS=',' read -r -a print_ports <<<"$PORT_LIST_CSV"
  echo "    其他端口订阅："
  for pt in "${print_ports[@]}"; do
    [ "$pt" = "$HY2_PORT" ] && continue
    if [ -f "${CLASH_WEB_DIR}/clash_${pt}.yaml" ]; then
      echo "    http://${SELECTED_IP}:${HTTP_PORT}/clash_${pt}.yaml"
    fi
  done
fi
echo
echo "提示：导入订阅后，在 Clash 客户端将 Proxy 组或 Stream/Game/VoIP 组指向你的节点并测试。"
# ---- helper: 生成自签证书并导入到 /acme/shared ----
generate_self_signed_cert() {
  local dom="${SWITCHED_DOMAIN:-$HY2_DOMAIN}"
  local ip="$SELECTED_IP"
  mkdir -p /acme/shared
  if ! command -v openssl >/dev/null 2>&1; then
    echo "[*] 未检测到 openssl，尝试自动安装..."
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y openssl >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
      yum install -y openssl >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y openssl >/dev/null 2>&1 || true
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache openssl >/dev/null 2>&1 || true
    fi
  fi
  if command -v openssl >/dev/null 2>&1; then
    echo "[*] 生成自签证书（包含 IP SAN）..."
    # 构造 SAN 扩展：若未设置域名，仅使用 IP SAN
    local san_ext
    if [ -n "$dom" ]; then
      san_ext="subjectAltName=DNS:${dom},IP:${ip}"
    else
      san_ext="subjectAltName=IP:${ip}"
    fi
    # CN 为空时回退为 IP，确保兼容性
    local cn_val
    cn_val="${dom:-$ip}"
    # 兼容性优先，尝试添加 SAN；若 -addext 不可用，退化为无 SAN
    if openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /acme/shared/privkey.pem -out /acme/shared/fullchain.pem \
      -days 365 -subj "/CN=${cn_val}" -addext "$san_ext" >/dev/null 2>&1; then
      :
    else
      openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /acme/shared/privkey.pem -out /acme/shared/fullchain.pem \
        -days 365 -subj "/CN=${cn_val}" >/dev/null 2>&1 || true
    fi
    # 计算 SPKI pin（供客户端使用 pinSHA256，避免 insecure）
    PIN_SHA256="$(openssl x509 -pubkey -in /acme/shared/fullchain.pem 2>/dev/null | \
      openssl pkey -pubin -outform DER 2>/dev/null | \
      openssl dgst -sha256 -binary 2>/dev/null | base64 2>/dev/null)"
    PIN_SHA256="${PIN_SHA256:-}"
    USE_EXISTING_CERT=1
    USE_CERT_PATH="/acme/shared/fullchain.pem"
    USE_KEY_PATH="/acme/shared/privkey.pem"
    echo "[OK] 自签证书已生成并导入 /acme/shared"
  else
    echo "[ERROR] 无 openssl，无法生成自签证书。请安装 openssl 或释放 80 端口以使用 ACME。"
  fi
}
