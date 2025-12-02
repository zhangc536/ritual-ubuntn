#!/usr/bin/env bash
set -euo pipefail

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
  disable_http_challenge: false
  disable_tlsalpn_challenge: true
EOF
  fi
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
  systemctl enable --now "hysteria-server@${port}" || true
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

# ---- helper: 在 ACME 成功后尝试从常见路径导入主服务证书 ----
try_import_main_cert_shared() {
  # 仅在当前未检测到 /acme 证书时尝试导入
  if [ "$USE_EXISTING_CERT" -eq 1 ]; then
    return 0
  fi

  local domain="$HY2_DOMAIN"
  # 常见缓存目录（autocert/hysteria 可能使用）
  local candidates=(
    "/root/.cache/autocert"
    "/root/.acme.sh"
    "/var/lib/hysteria"
    "/etc/hysteria"
    "/var/cache/hysteria"
  )

  local found_cert="" found_key=""
  for d in "${candidates[@]}"; do
    [ -d "$d" ] || continue
    # 先找证书
    found_cert="$(find "$d" -maxdepth 2 -type f \( -name "*fullchain*.pem" -o -name "*${domain}*.crt" -o -name "*${domain}*.cer" -o -name "*cert*.pem" \) 2>/dev/null | head -n1)"
    # 再找私钥
    found_key="$(find "$d" -maxdepth 2 -type f \( -name "*privkey*.pem" -o -name "*${domain}*.key" -o -name "*key*.pem" \) 2>/dev/null | head -n1)"
    if [ -n "$found_cert" ] && [ -n "$found_key" ]; then
      mkdir -p /acme/shared
      # 尝试复制到统一共享路径
      cp -f "$found_cert" /acme/shared/fullchain.pem 2>/dev/null || cat "$found_cert" > /acme/shared/fullchain.pem
      cp -f "$found_key" /acme/shared/privkey.pem 2>/dev/null || cat "$found_key" > /acme/shared/privkey.pem
      USE_EXISTING_CERT=1
      USE_CERT_PATH="/acme/shared/fullchain.pem"
      USE_KEY_PATH="/acme/shared/privkey.pem"
      echo "[OK] 已从主服务导入证书到 /acme/shared，并将用于多端口实例"
      return 0
    fi
  done

  echo "[WARN] 未能定位主服务证书缓存文件，仍将仅运行主端口。若需多端口，请将证书放入 /acme/<dir>/fullchain.pem 与 privkey.pem。"
  return 1
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
# 2) 生成域名（sslip.io -> nip.io -> xip.io -> warn）
# ===========================
IP_DASH="${SELECTED_IP//./-}"
IP_DOT="${SELECTED_IP}"

# 定义域名服务列表，按优先级排序
DOMAIN_SERVICES=("sslip.io" "nip.io" "xip.io")
HY2_DOMAIN=""

echo "[*] 检测可用的域名解析服务..."

# 遍历域名服务，找到第一个可用的
for service in "${DOMAIN_SERVICES[@]}"; do
  if [ "$service" = "xip.io" ]; then
    # xip.io 使用点分格式
    test_domain="${IP_DOT}.${service}"
  else
    # sslip.io 和 nip.io 使用横线格式
    test_domain="${IP_DASH}.${service}"
  fi
  
  echo "[*] 测试 ${service}: ${test_domain}"
  
  # 多重检查域名解析可用性
  resolved_ip=""
  
  # 方法1: 使用 getent
  resolved_ip="$(getent ahostsv4 "$test_domain" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
  
  # 方法2: 如果 getent 失败，尝试 nslookup
  if [ -z "$resolved_ip" ] && command -v nslookup >/dev/null 2>&1; then
    resolved_ip="$(nslookup "$test_domain" 2>/dev/null | awk '/^Address: / { print $2 }' | head -n1 || true)"
  fi
  
  # 方法3: 如果还是失败，尝试 dig
  if [ -z "$resolved_ip" ] && command -v dig >/dev/null 2>&1; then
    resolved_ip="$(dig +short "$test_domain" A 2>/dev/null | head -n1 || true)"
  fi
  
  # 验证解析结果
  if [ -n "$resolved_ip" ] && [ "$resolved_ip" = "$SELECTED_IP" ]; then
    HY2_DOMAIN="$test_domain"
    echo "[OK] ${service} 解析正常: ${test_domain} -> ${resolved_ip}"
    
    # 额外验证：尝试 HTTP 连接测试（可选）
    if command -v curl >/dev/null 2>&1; then
      if curl -s --connect-timeout 3 "http://${test_domain}:80" >/dev/null 2>&1 || [ $? -eq 7 ]; then
        echo "[OK] ${service} HTTP 连接测试通过"
      else
        echo "[INFO] ${service} HTTP 连接测试失败，但域名解析正常"
      fi
    fi
    break
  else
    echo "[WARN] ${service} 解析失败或不匹配: ${test_domain} -> ${resolved_ip:-"无解析"}"
  fi
done

# 如果所有服务都不可用，发出警告但继续使用 sslip.io
if [ -z "$HY2_DOMAIN" ]; then
  HY2_DOMAIN="${IP_DASH}.sslip.io"
  echo "[WARN] 所有域名解析服务（sslip.io/nip.io/xip.io）都无法正确解析到 ${SELECTED_IP}。"
  echo "       将使用 ${HY2_DOMAIN}，但 ACME HTTP-01 可能失败。"
  echo "       请确保域名解析到本机且 80/tcp 可达。"
fi
echo "[OK] 使用域名/IP：${HY2_DOMAIN} -> ${SELECTED_IP}"

# ===========================
# 3) 安装 hysteria 二进制（若不存在）
# ===========================
if ! command -v hysteria >/dev/null 2>&1; then
  echo "[*] 安装 hysteria ..."
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

if [ "$USE_EXISTING_CERT" -eq 0 ]; then
  echo "[INFO] /acme 下未找到证书，尝试从主服务缓存自动导入..."
  if try_import_main_cert_shared; then
    echo "[OK] 已自动导入主证书到 /acme/shared，将用于多端口实例"
  else
    echo "[INFO] 脚本将尝试 ACME HTTP-01（需 80/tcp 可达）"
  fi
fi

# ===========================
# 6) 写 hysteria 配置（使用已找到的证书或 ACME 配置）
# ===========================
mkdir -p /etc/hysteria
if [ "$USE_EXISTING_CERT" -eq 1 ]; then
  cat >/etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}

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
  echo "[OK] 已写入 hysteria 配置（使用 /acme 证书）"
  # 多端口：为额外端口写 TLS 配置文件
  if [ -n "${HY2_PORTS:-}" ]; then
    IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
    for pt in "${ports_all[@]}"; do
      if [ "$pt" != "$HY2_PORT" ]; then
        write_hysteria_config_for_port "$pt" "${PASS_MAP[$pt]}" "${OBFS_MAP[$pt]}" "1"
      fi
    done
  fi
else
  mkdir -p /acme/autocert
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
  dir: /acme/autocert
  disable_http_challenge: false
  disable_tlsalpn_challenge: true
EOF
  echo "[OK] 已写入 hysteria 配置（使用 ACME HTTP-01）"
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
systemctl enable --now hysteria-server
sleep 3
systemctl restart hysteria-server || true

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
      echo "[WARN] 检测到 HTTP 429 速率限制错误，尝试切换域名..."
      break
    fi
    
    sleep 5
    TRIES=$((TRIES+1))
  done

  # 处理速率限制：尝试切换到下一个可用域名
  if [ "$RATE_LIMITED" -eq 1 ]; then
    echo "[*] 由于 HTTP 429 错误，尝试切换到备用域名服务..."
    
    # 获取当前使用的域名服务
    CURRENT_SERVICE=""
    if echo "$HY2_DOMAIN" | grep -q "sslip.io"; then
      CURRENT_SERVICE="sslip.io"
    elif echo "$HY2_DOMAIN" | grep -q "nip.io"; then
      CURRENT_SERVICE="nip.io"
    elif echo "$HY2_DOMAIN" | grep -q "xip.io"; then
      CURRENT_SERVICE="xip.io"
    fi
    
    # 尝试切换到下一个域名服务
    SWITCHED=0
    for service in "${DOMAIN_SERVICES[@]}"; do
      # 跳过当前已使用的服务
      if [ "$service" = "$CURRENT_SERVICE" ]; then
        continue
      fi
      
      # 生成新的测试域名
      if [ "$service" = "xip.io" ]; then
        new_domain="${IP_DOT}.${service}"
      else
        new_domain="${IP_DASH}.${service}"
      fi
      
      echo "[*] 尝试切换到 ${service}: ${new_domain}"
      
      # 快速验证新域名
      resolved_ip="$(getent ahostsv4 "$new_domain" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
      if [ -n "$resolved_ip" ] && [ "$resolved_ip" = "$SELECTED_IP" ]; then
        echo "[OK] ${service} 解析验证成功，切换域名..."
        HY2_DOMAIN="$new_domain"
        SWITCHED=1
        
        # 停止当前服务
        systemctl stop hysteria-server 2>/dev/null || true
        
        # 重新生成配置文件（保持与初始逻辑一致）
        # 根据是否存在现有证书选择 tls 或 acme 写法
        cat >/etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}

auth:
  type: password
  password: ${HY2_PASS}

obfs:
  type: salamander
  salamander:
    password: ${OBFS_PASS}
EOF
        if [ "$USE_EXISTING_CERT" -eq 1 ]; then
          cat >>/etc/hysteria/config.yaml <<EOF

tls:
  cert: ${USE_CERT_PATH}
  key: ${USE_KEY_PATH}
EOF
        else
          cat >>/etc/hysteria/config.yaml <<EOF

acme:
  domains:
    - ${HY2_DOMAIN}
  disable_http_challenge: false
  disable_tlsalpn_challenge: true
EOF
        fi
        
        # 重启服务
         systemctl start hysteria-server
         echo "[OK] 已切换到 ${service}，重新启动证书申请..."
         
         # 更新 Clash 配置文件中的域名
         echo "[*] 更新 Clash 订阅配置中的域名..."
         if [ -f "${CLASH_OUT_PATH}" ]; then
           # 重新生成 Clash 配置
           TMPF="${CLASH_OUT_PATH}.tmp"
           TARGET="${CLASH_OUT_PATH}"
           
           # 重新转义新域名
           DOMAIN_ESC="$(escape_for_sed "${HY2_DOMAIN}")"
           
           # 从模板重新生成（需要先创建临时模板）
           cat >"${TMPF}" <<EOF
mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
external-controller: '127.0.0.1:9090'

dns:
  enable: true
  ipv6: false
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
    sni: __HY2_DOMAIN__

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
           
           # 执行变量替换
           NAME_ESC="$(escape_for_sed "${NAME_TAG}")"
           IP_ESC="$(escape_for_sed "${SELECTED_IP}")"
           PORT_ESC="$(escape_for_sed "${HY2_PORT}")"
           PASS_ESC="$(escape_for_sed "${HY2_PASS}")"
           OBFS_ESC="$(escape_for_sed "${OBFS_PASS}")"
           
           sed -e "s@__NAME_TAG__@${NAME_ESC}@g" \
               -e "s@__SELECTED_IP__@${IP_ESC}@g" \
               -e "s@__HY2_PORT__@${PORT_ESC}@g" \
               -e "s@__HY2_PASS__@${PASS_ESC}@g" \
               -e "s@__OBFS_PASS__@${OBFS_ESC}@g" \
               -e "s@__HY2_DOMAIN__@${DOMAIN_ESC}@g" \
               "${TMPF}" > "${TARGET}"
           rm -f "${TMPF}"
           
           echo "[OK] Clash 订阅配置已更新为新域名: ${HY2_DOMAIN}"
         fi
         
         # 重新等待证书申请
         TRIES=0
         ACME_OK=0
         while [ $TRIES -lt 12 ]; do
           if journalctl -u hysteria-server --no-pager -n 100 | grep -E -iq "(certificate obtained successfully|acme_client.*authorization finalized|acme.*valid)"; then
             ACME_OK=1
             echo "[OK] 域名切换后证书申请成功"
             break
           fi
           sleep 5
           TRIES=$((TRIES+1))
         done
         break
      else
        echo "[WARN] ${service} 解析验证失败，尝试下一个服务"
      fi
    done
    
    if [ "$SWITCHED" -eq 0 ]; then
      echo "[ERROR] 无法找到可用的备用域名服务"
    fi
  fi

  if [ "$ACME_OK" -ne 1 ] && [ "$RATE_LIMITED" -eq 0 ]; then
    echo "[WARN] 未检测到 ACME 成功日志，但可能证书已申请成功。检查日志详情："
    journalctl -u hysteria-server -n 50 --no-pager | grep -E -i "(acme|certificate|tls-alpn|http-01|challenge|429|rate.?limit)" || true
    echo "[INFO] 继续执行，证书可能已成功获取"
  elif [ "$ACME_OK" -eq 1 ]; then
    echo "[OK] ACME 证书申请成功检测到"
    # 若启用多端口，启动多实例（优先导入主证书；否则共享 ACME 缓存目录）
    if [ -n "${HY2_PORTS:-}" ]; then
      ensure_systemd_template
      IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
      # 尝试导入主证书
      if try_import_main_cert_shared; then
        use_tls_for_ports=1
      else
        use_tls_for_ports=0
      fi
      for pt in "${ports_all[@]}"; do
        [ "$pt" = "$HY2_PORT" ] && continue
        if [ "$use_tls_for_ports" -eq 1 ]; then
          write_hysteria_config_for_port "$pt" "${PASS_MAP[$pt]}" "${OBFS_MAP[$pt]}" "1"
        else
          write_hysteria_config_for_port "$pt" "${PASS_MAP[$pt]}" "${OBFS_MAP[$pt]}" "0"
        fi
        start_hysteria_instance "$pt"
      done
      ensure_udp_ports_open "$PORT_LIST_CSV"
    fi
  fi
else
  echo "[OK] 使用现有 /acme 证书，跳过 ACME 等待"
fi

setup_auto_reboot_cron

echo "=== 监听检查（UDP/${HY2_PORT}) ==="
ss -lunp | grep -E ":${HY2_PORT}\b" || true
if [ -n "${HY2_PORTS:-}" ]; then
  echo "=== 监听检查（其他端口） ==="
  IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
  for pt in "${ports_all[@]}"; do
    if [ "$pt" != "$HY2_PORT" ]; then
      ss -lunp | grep -E ":${pt}\b" || true
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

URI="hysteria2://${PASS_ENC}@${SELECTED_IP}:${HY2_PORT}/?protocol=udp&obfs=salamander&obfs-password=${OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"

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
    P_URI="hysteria2://${P_PASS_ENC}@${SELECTED_IP}:${pt}/?protocol=udp&obfs=salamander&obfs-password=${P_OBFS_ENC}&sni=${HY2_DOMAIN}&insecure=0&pinSHA256=${PIN_ENC}#${NAME_ENC}"
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
    sni: __HY2_DOMAIN__

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
DOMAIN_ESC="$(escape_for_sed "${HY2_DOMAIN}")"

sed -e "s@__NAME_TAG__@${NAME_ESC}@g" \
    -e "s@__SELECTED_IP__@${IP_ESC}@g" \
    -e "s@__HY2_PORT__@${PORT_ESC}@g" \
    -e "s@__HY2_PASS__@${PASS_ESC}@g" \
    -e "s@__OBFS_PASS__@${OBFS_ESC}@g" \
    -e "s@__HY2_DOMAIN__@${DOMAIN_ESC}@g" \
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
    sni: __HY2_DOMAIN__

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
    DOMAIN_ESC2="$(escape_for_sed "${HY2_DOMAIN}")"
    sed -e "s@__NAME_TAG__@${NAME_ESC2}@g" \
        -e "s@__SELECTED_IP__@${IP_ESC2}@g" \
        -e "s@__HY2_PORT__@${PORT_ESC2}@g" \
        -e "s@__HY2_PASS__@${PASS_ESC2}@g" \
        -e "s@__OBFS_PASS__@${OBFS_ESC2}@g" \
        -e "s@__HY2_DOMAIN__@${DOMAIN_ESC2}@g" \
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
