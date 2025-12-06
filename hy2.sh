#!/usr/bin/env bash
set -euo pipefail

# =============================================================
# 脚本顺序概览（执行主流程）：
#  0) 选择模式（全新安装 / 仅维护任务）
#  1) 获取公网 IPv4
#  2) 安装依赖（如缺失）
#  3) 域名处理（支持自定义域名；动态域名服务已移除）
#  4) 安装 hysteria 二进制（若不存在）
#  5) 生成主/多端口密码与端口列表（如未提供）
#  6) 生成自签证书（含 IP SAN，域名可选作为 CN/SAN）并计算指纹
#  7) 写主端口与多端口配置并启动（始终 TLS，自签证书）
#  8) 打印进程与监听检查、构造 URI、生成 Clash 订阅并通过 Nginx 提供
#
# 说明：所有 helper 函数在前置定义；主流程按以上顺序执行，避免“未定义函数”或“端口占用”导致失败。
# =============================================================

# ===== 可改参数 =====
HY2_PORT="${HY2_PORT:-443}"           # Hysteria2 UDP端口（默认 443，更易穿透）
HY2_PORTS="${HY2_PORTS:-}"            # 多端口（逗号分隔，例如 8443,8444,8445）
HY2_PORT_COUNT="${HY2_PORT_COUNT:-}"  # 端口数量（若未提供 HY2_PORTS，则按数量从主端口递增）
HY2_PASS="${HY2_PASS:-}"              # HY2 密码（留空自动生成）
OBFS_PASS="${OBFS_PASS:-}"            # 混淆密码（留空自动生成）
DISABLE_OBFS="${DISABLE_OBFS:-1}"     # 关闭混淆（1=关闭，其余=开启）
NAME_TAG="${NAME_TAG:-MyHysteria}"    # 节点名称
PIN_SHA256="${PIN_SHA256:-}"          # 证书指纹（可留空）

CLASH_WEB_DIR="${CLASH_WEB_DIR:-/etc/hysteria}"
CLASH_OUT_PATH="${CLASH_OUT_PATH:-${CLASH_WEB_DIR}/clash_subscription.yaml}"
CLASH_LOG_LEVEL="${CLASH_LOG_LEVEL:-info}"
ENABLE_URLTEST="${ENABLE_URLTEST:-1}"
CLASH_URLTEST_URL="${CLASH_URLTEST_URL:-https://www.gstatic.com/generate_204}"
CLASH_URLTEST_INTERVAL="${CLASH_URLTEST_INTERVAL:-300}"
CLASH_URLTEST_TOLERANCE="${CLASH_URLTEST_TOLERANCE:-50}"
ENABLE_FALLBACK="${ENABLE_FALLBACK:-1}"

HTTP_PORT="${HTTP_PORT:-8080}"

# 极限抗丢包默认开启（可通过环境变量关闭/调参）
DISABLE_GRO_GSO="${DISABLE_GRO_GSO:-1}"      # 关闭聚合/分段（1=关闭），降低尾延迟与乱序
ENABLE_TC_QDISC="${ENABLE_TC_QDISC:-2}"      # 开启 tc 队列（1=fq_codel，2=cake）
TC_MAX_RATE="${TC_MAX_RATE:-}"               # 可选：限速，配合 fq_codel/cake（如 1000mbit）
NOTRACK_UDP="${NOTRACK_UDP:-1}"              # 跳过 UDP conntrack（1=启用），降低高并发丢包
CONNTRACK_MAX="${CONNTRACK_MAX:-1048576}"    # 可选：提高 conntrack 表大小（如 1048576）

# 进一步优化：可选 DSCP 标记与队列参数、网卡环形缓冲
ENABLE_DSCP="${ENABLE_DSCP:-0}"              # 为 UDP 流量标记 DSCP（仅本机出站有效）
DSCP_OUT_CLASS="${DSCP_OUT_CLASS:-EF}"       # 出站标记的 DSCP 类（如 EF/CS7/AF31，也可数值）
DSCP_IN_CLASS="${DSCP_IN_CLASS:-}"           # 可选：对入站包标记 DSCP（通常仅用于本机转发队列分类）
TC_CAKE_DIFFSERV="${TC_CAKE_DIFFSERV:-diffserv3}"  # cake diffserv 模式（diffserv3/diffserv4/diffserv8）
TC_CAKE_OPTS="${TC_CAKE_OPTS:-}"             # 额外 cake 参数（例如 nat）
TC_FQ_CODEL_OPTS="${TC_FQ_CODEL_OPTS:-}"     # 额外 fq_codel 参数（例如 flows 1024）
SET_NIC_RING="${SET_NIC_RING:-0}"            # 调整网卡环形缓冲（1=启用）
RX_RING="${RX_RING:-4096}"                   # RX 环形缓冲目标值
TX_RING="${TX_RING:-4096}"                   # TX 环形缓冲目标值

# 运行时网络调优参数（可覆盖默认值）
NET_RMEM_MAX="${NET_RMEM_MAX:-33554432}"
NET_WMEM_MAX="${NET_WMEM_MAX:-33554432}"
NET_RMEM_DEF="${NET_RMEM_DEF:-262144}"
NET_WMEM_DEF="${NET_WMEM_DEF:-262144}"
NET_BACKLOG="${NET_BACKLOG:-250000}"
UDP_RMEM_MIN="${UDP_RMEM_MIN:-16384}"
UDP_WMEM_MIN="${UDP_WMEM_MIN:-16384}"
DEFAULT_QDISC="${DEFAULT_QDISC:-fq}"

# 低延迟相关：Busy Poll 与网卡中断合并（可选）
ENABLE_BUSY_POLL="${ENABLE_BUSY_POLL:-1}"     # 启用忙轮询/预算调优（提升低延迟，增 CPU）
NET_BUSY_POLL="${NET_BUSY_POLL:-50}"          # 微秒
NET_BUSY_READ="${NET_BUSY_READ:-50}"          # 微秒
NETDEV_BUDGET_USECS="${NETDEV_BUDGET_USECS:-80}" # NAPI 每轮最大耗时微秒
NETDEV_BUDGET="${NETDEV_BUDGET:-300}"         # NAPI 一轮最大包数预算
DEV_WEIGHT="${DEV_WEIGHT:-64}"                 # 设备权重（每轮处理包数的基线）
SET_NIC_COALESCE="${SET_NIC_COALESCE:-0}"      # 启用网卡中断合并（1=启用）
RX_COALESCE_USECS="${RX_COALESCE_USECS:-16}"   # RX 中断合并微秒
TX_COALESCE_USECS="${TX_COALESCE_USECS:-16}"   # TX 中断合并微秒

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
  cat >"/etc/hysteria/config-${port}.yaml" <<EOF
listen: :${port}
protocol: udp

auth:
  type: password
  password: ${pass}
EOF
  if [ "${DISABLE_OBFS}" != "1" ]; then
    cat >>"/etc/hysteria/config-${port}.yaml" <<EOF
obfs:
  type: salamander
  salamander:
    password: ${obfsp}
EOF
  fi
  cat >>"/etc/hysteria/config-${port}.yaml" <<EOF
tls:
  cert: ${USE_CERT_PATH}
  key: ${USE_KEY_PATH}
EOF
}

# ---- helper: 写主端口 /etc/hysteria/config.yaml（始终 TLS，自签证书） ----
write_hysteria_main_config() {
  local use_tls="$1"
  mkdir -p /etc/hysteria
  cat >/etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}
protocol: udp

auth:
  type: password
  password: ${HY2_PASS}
EOF
  if [ "${DISABLE_OBFS}" != "1" ]; then
    cat >>/etc/hysteria/config.yaml <<EOF
obfs:
  type: salamander
  salamander:
    password: ${OBFS_PASS}
EOF
  fi
  cat >>/etc/hysteria/config.yaml <<EOF
tls:
  cert: ${USE_CERT_PATH}
  key: ${USE_KEY_PATH}
EOF
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
RestartSec=1
LimitNOFILE=1048576
NoNewPrivileges=true

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
  elif command -v iptables >/dev/null 2>&1; then
    IFS=',' read -r -a ports <<<"$list_csv"
    for pt in "${ports[@]}"; do
      iptables -C INPUT -p udp --dport "$pt" -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p udp --dport "$pt" -j ACCEPT >/dev/null 2>&1 || true
    done
    echo "[OK] iptables 已放行指定 UDP 端口"
    opened=1
  elif command -v nft >/dev/null 2>&1; then
    IFS=',' read -r -a ports <<<"$list_csv"
    for pt in "${ports[@]}"; do
      nft add rule inet filter input udp dport "$pt" accept >/dev/null 2>&1 || true
    done
    echo "[OK] nftables 已尝试放行指定 UDP 端口"
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

# ---- helper: 开放 TCP 端口（按需） ----
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
  elif command -v iptables >/dev/null 2>&1; then
    IFS=',' read -r -a ports <<<"$list_csv"
    for pt in "${ports[@]}"; do
      iptables -C INPUT -p tcp --dport "$pt" -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT -p tcp --dport "$pt" -j ACCEPT >/dev/null 2>&1 || true
    done
    echo "[OK] iptables 已放行指定 TCP 端口"
    opened=1
  elif command -v nft >/dev/null 2>&1; then
    IFS=',' read -r -a ports <<<"$list_csv"
    for pt in "${ports[@]}"; do
      nft add rule inet filter input tcp dport "$pt" accept >/dev/null 2>&1 || true
    done
    echo "[OK] nftables 已尝试放行指定 TCP 端口"
    opened=1
  fi
  if [ "$opened" -eq 0 ]; then
    echo "[WARN] 未检测到 firewalld/ufw；若存在其他防火墙或云安全组，请手动放行 TCP 端口。"
  fi
}

# ---- helper: 兼容占位：80 端口可用性检查（已移除 ACME 相关逻辑） ----
STOPPED_NGINX=0
STOPPED_APACHE=0
STOPPED_CADDY=0
STOPPED_TRAEFIK=0
PORT80_FREE=1
ensure_port_80_available() { :; }

restore_port_80_services_if_stopped() { :; }

# ACME 预申请逻辑已移除（改为始终使用自签证书）
try_issue_cert_preflight() {
  return 1
}
 

# ---- helper: 在 ACME 成功后尝试从常见路径导入主服务证书（已移除） ----
try_import_main_cert_shared() { return 1; }

# ---- helper: 从 Nginx 配置导入证书（已移除） ----
try_import_from_nginx_configs() { return 1; }

# ---- helper: 从 Apache 配置导入证书（已移除） ----
try_import_from_apache_configs() { return 1; }

# ---- helper: 从 Caddy 存储导入证书（已移除） ----
try_import_from_caddy_storage() { return 1; }

# ---- helper: 从 Traefik acme.json 导入证书（已移除） ----
try_import_from_traefik_acme_json() { return 1; }

# ---- helper: 使用 ACME 缓存目录启动额外端口（已移除） ----
start_additional_instances_with_acme_cache() { return 0; }

# ---- helper: 运行时网络调优（仅当前会话，非持久化） ----
apply_runtime_net_tuning() {
  if [ "${ENABLE_NET_TUNE:-1}" != "1" ]; then
    echo "[INFO] 网络调优已禁用（ENABLE_NET_TUNE=0）"
    return 0
  fi
  # 提升 UDP 缓冲与排队，启用低抖动队列
  sysctl -w net.core.rmem_max="${NET_RMEM_MAX}" >/dev/null 2>&1 || true
  sysctl -w net.core.wmem_max="${NET_WMEM_MAX}" >/dev/null 2>&1 || true
  sysctl -w net.core.rmem_default="${NET_RMEM_DEF}" >/dev/null 2>&1 || true
  sysctl -w net.core.wmem_default="${NET_WMEM_DEF}" >/dev/null 2>&1 || true
  sysctl -w net.core.netdev_max_backlog="${NET_BACKLOG}" >/dev/null 2>&1 || true
  sysctl -w net.core.default_qdisc="${DEFAULT_QDISC}" >/dev/null 2>&1 || true
  sysctl -w net.ipv4.udp_rmem_min="${UDP_RMEM_MIN}" >/dev/null 2>&1 || true
  sysctl -w net.ipv4.udp_wmem_min="${UDP_WMEM_MIN}" >/dev/null 2>&1 || true

  # 低延迟：忙轮询与 NAPI 预算（风险：增 CPU 占用）
  if [ "${ENABLE_BUSY_POLL}" = "1" ]; then
    sysctl -w net.core.busy_poll="${NET_BUSY_POLL}" >/dev/null 2>&1 || true
    sysctl -w net.core.busy_read="${NET_BUSY_READ}" >/dev/null 2>&1 || true
    sysctl -w net.core.netdev_budget_usecs="${NETDEV_BUDGET_USECS}" >/dev/null 2>&1 || true
    sysctl -w net.core.netdev_budget="${NETDEV_BUDGET}" >/dev/null 2>&1 || true
    sysctl -w net.core.dev_weight="${DEV_WEIGHT}" >/dev/null 2>&1 || true
    echo "[OK] 已启用 Busy Poll/预算调优：busy_poll=${NET_BUSY_POLL}us busy_read=${NET_BUSY_READ}us budget_usecs=${NETDEV_BUDGET_USECS} budget=${NETDEV_BUDGET} dev_weight=${DEV_WEIGHT}"
  else
    echo "[INFO] Busy Poll 已禁用（ENABLE_BUSY_POLL=0）"
  fi
  echo "[OK] 已应用运行时网络调优参数"
}

# ---- helper: 检测默认出口网卡 ----
detect_main_iface() {
  local iface=""
  if command -v ip >/dev/null 2>&1; then
    iface="$(ip route get 1 2>/dev/null | awk '/dev/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
  fi
  echo "${iface}"
}

# ---- helper: DSCP 名称到数值的简易映射（常见类）。返回空表示未知。----
dscp_to_value() {
  local cls="$1"
  case "$cls" in
    EF|ef) echo 46 ;;
    CS0|cs0) echo 0 ;;
    CS1|cs1) echo 8 ;;
    CS2|cs2) echo 16 ;;
    CS3|cs3) echo 24 ;;
    CS4|cs4) echo 32 ;;
    CS5|cs5) echo 40 ;;
    CS6|cs6) echo 48 ;;
    CS7|cs7) echo 56 ;;
    AF11|af11) echo 10 ;;
    AF12|af12) echo 12 ;;
    AF13|af13) echo 14 ;;
    AF21|af21) echo 18 ;;
    AF22|af22) echo 20 ;;
    AF23|af23) echo 22 ;;
    AF31|af31) echo 26 ;;
    AF32|af32) echo 28 ;;
    AF33|af33) echo 30 ;;
    AF41|af41) echo 34 ;;
    AF42|af42) echo 36 ;;
    AF43|af43) echo 38 ;;
    * )
      # 如果是纯数字则直接返回
      if printf '%s' "$cls" | grep -Eq '^[0-9]+$'; then
        echo "$cls"
      else
        echo "" # 未知
      fi
      ;;
  esac
}

# ---- helper: 极限抗丢包（可选，默认关闭） ----
apply_extreme_loss_mitigation() {
  local iface="$(detect_main_iface)"
  [ -z "$iface" ] && echo "[WARN] 未能检测到主网卡，跳过极限抗丢包步骤" && return 0

  # 1) 可选关闭 GRO/GSO（减少聚合与乱序导致的尾延迟/重传）
  if [ "${DISABLE_GRO_GSO}" = "1" ] && command -v ethtool >/dev/null 2>&1; then
    ethtool -K "$iface" gro off gso off >/dev/null 2>&1 || true
    echo "[OK] 已关闭 $iface 的 GRO/GSO"
  fi

  # 2) 可选应用 tc 队列控制（抗 bufferbloat）
  if [ "${ENABLE_TC_QDISC}" != "0" ] && command -v tc >/dev/null 2>&1; then
    if [ "${ENABLE_TC_QDISC}" = "2" ]; then
      # cake 更智能（若内核/模块支持），可选带宽参数
      if tc qdisc replace dev "$iface" root cake ${TC_MAX_RATE:+bandwidth $TC_MAX_RATE} ${TC_CAKE_DIFFSERV:+$TC_CAKE_DIFFSERV} ${TC_CAKE_OPTS} >/dev/null 2>&1; then
        echo "[OK] 已在 $iface 应用 cake qdisc${TC_MAX_RATE:+（带宽 $TC_MAX_RATE）}${TC_CAKE_DIFFSERV:+，$TC_CAKE_DIFFSERV}${TC_CAKE_OPTS:+，$TC_CAKE_OPTS}"
      else
        echo "[WARN] cake 不可用，尝试 fq_codel"
        tc qdisc replace dev "$iface" root fq_codel ${TC_FQ_CODEL_OPTS} >/dev/null 2>&1 || true
        echo "[OK] 已在 $iface 应用 fq_codel${TC_FQ_CODEL_OPTS:+（$TC_FQ_CODEL_OPTS）}"
      fi
    else
      tc qdisc replace dev "$iface" root fq_codel ${TC_FQ_CODEL_OPTS} >/dev/null 2>&1 || true
      echo "[OK] 已在 $iface 应用 fq_codel${TC_FQ_CODEL_OPTS:+（$TC_FQ_CODEL_OPTS）}"
    fi
  fi

  # 3) 可选跳过 UDP conntrack（降低 nf_conntrack 开销与爆表导致的丢包）
  if [ "${NOTRACK_UDP}" = "1" ]; then
    local ports_csv="$PORT_LIST_CSV"
    IFS=',' read -r -a ports <<<"$ports_csv"
    if command -v iptables >/dev/null 2>&1; then
      for pt in "${ports[@]}"; do
        iptables -t raw -C PREROUTING -p udp --dport "$pt" -j NOTRACK >/dev/null 2>&1 || iptables -t raw -I PREROUTING -p udp --dport "$pt" -j NOTRACK >/dev/null 2>&1 || true
        iptables -t raw -C OUTPUT -p udp --sport "$pt" -j NOTRACK >/dev/null 2>&1 || iptables -t raw -I OUTPUT -p udp --sport "$pt" -j NOTRACK >/dev/null 2>&1 || true
      done
      echo "[OK] iptables raw NOTRACK 已应用于 UDP 端口"
    elif command -v nft >/dev/null 2>&1; then
      for pt in "${ports[@]}"; do
        nft add rule inet raw prerouting udp dport "$pt" notrack >/dev/null 2>&1 || true
        nft add rule inet raw output udp sport "$pt" notrack >/dev/null 2>&1 || true
      done
      echo "[OK] nftables raw notrack 已应用于 UDP 端口"
    else
      echo "[WARN] 未找到 iptables/nft，无法应用 notrack"
    fi
  fi

  # 4) 可选提高 conntrack 表上限（在未启用 notrack 时降低爆表掉包）
  if [ -n "${CONNTRACK_MAX}" ]; then
    sysctl -w net.netfilter.nf_conntrack_max="${CONNTRACK_MAX}" >/dev/null 2>&1 || true
    echo "[OK] 已设置 nf_conntrack_max=${CONNTRACK_MAX}"
  fi

  # 5) 可选 DSCP 流量标记（用于 egress 队列分类与优先级）
  if [ "${ENABLE_DSCP}" = "1" ]; then
    local ports_csv="$PORT_LIST_CSV"
    IFS=',' read -r -a ports <<<"$ports_csv"
    if command -v iptables >/dev/null 2>&1; then
      for pt in "${ports[@]}"; do
        # 出站包：源端口为服务端端口
        local _outv; _outv="$(dscp_to_value "$DSCP_OUT_CLASS")"
        if [ -n "$_outv" ]; then
          iptables -t mangle -C POSTROUTING -p udp --sport "$pt" -j DSCP --set-dscp "$_outv" >/dev/null 2>&1 || \
          iptables -t mangle -A POSTROUTING -p udp --sport "$pt" -j DSCP --set-dscp "$_outv" >/dev/null 2>&1 || true
        else
          iptables -t mangle -C POSTROUTING -p udp --sport "$pt" -j DSCP --set-dscp-class "$DSCP_OUT_CLASS" >/dev/null 2>&1 || \
          iptables -t mangle -A POSTROUTING -p udp --sport "$pt" -j DSCP --set-dscp-class "$DSCP_OUT_CLASS" >/dev/null 2>&1 || true
        fi
        # 入站包（可选）：目标端口为服务端端口
        if [ -n "${DSCP_IN_CLASS}" ]; then
          local _inv; _inv="$(dscp_to_value "$DSCP_IN_CLASS")"
          if [ -n "$_inv" ]; then
            iptables -t mangle -C PREROUTING -p udp --dport "$pt" -j DSCP --set-dscp "$_inv" >/dev/null 2>&1 || \
            iptables -t mangle -A PREROUTING -p udp --dport "$pt" -j DSCP --set-dscp "$_inv" >/dev/null 2>&1 || true
          else
            iptables -t mangle -C PREROUTING -p udp --dport "$pt" -j DSCP --set-dscp-class "$DSCP_IN_CLASS" >/dev/null 2>&1 || \
            iptables -t mangle -A PREROUTING -p udp --dport "$pt" -j DSCP --set-dscp-class "$DSCP_IN_CLASS" >/dev/null 2>&1 || true
          fi
        fi
      done
      echo "[OK] 已应用 DSCP 标记（iptables mangle）：出站 ${DSCP_OUT_CLASS}${DSCP_IN_CLASS:+，入站 $DSCP_IN_CLASS}"
    elif command -v nft >/dev/null 2>&1; then
      for pt in "${ports[@]}"; do
        local _outv; _outv="$(dscp_to_value "$DSCP_OUT_CLASS")"
        if [ -n "$_outv" ]; then
          nft add rule inet mangle postrouting udp sport "$pt" dscp set "$_outv" >/dev/null 2>&1 || true
        else
          echo "[WARN] DSCP_OUT_CLASS=${DSCP_OUT_CLASS} 未识别，nft 需数值，已跳过设置"
        fi
        if [ -n "${DSCP_IN_CLASS}" ]; then
          local _inv; _inv="$(dscp_to_value "$DSCP_IN_CLASS")"
          if [ -n "$_inv" ]; then
            nft add rule inet mangle prerouting udp dport "$pt" dscp set "$_inv" >/dev/null 2>&1 || true
          else
            echo "[WARN] DSCP_IN_CLASS=${DSCP_IN_CLASS} 未识别，nft 需数值，已跳过设置"
          fi
        fi
      done
      echo "[OK] 已应用 DSCP 标记（nftables mangle）：出站 ${DSCP_OUT_CLASS}${DSCP_IN_CLASS:+，入站 $DSCP_IN_CLASS}"
    else
      echo "[WARN] 未找到 iptables/nft，无法应用 DSCP 标记"
    fi
  fi

  # 6) 可选调整网卡环形缓冲（提升在高并发下的吞吐与抗丢包）
  if [ "${SET_NIC_RING}" = "1" ] && command -v ethtool >/dev/null 2>&1; then
    ethtool -G "$iface" rx "$RX_RING" tx "$TX_RING" >/dev/null 2>&1 || true
    echo "[OK] 已设置 $iface 环形缓冲：RX=$RX_RING TX=$TX_RING"
  fi

  # 7) 可选调整网卡中断合并（降低中断风暴，兼顾延迟）
  if [ "${SET_NIC_COALESCE}" = "1" ] && command -v ethtool >/dev/null 2>&1; then
    ethtool -C "$iface" rx-usecs "$RX_COALESCE_USECS" tx-usecs "$TX_COALESCE_USECS" >/dev/null 2>&1 || true
    echo "[OK] 已设置 $iface 中断合并：rx-usecs=$RX_COALESCE_USECS tx-usecs=$TX_COALESCE_USECS"
  fi
}

# ---- helper: 生成自签证书并导入到 /acme/shared ----
generate_self_signed_cert() {
  local dom="${SWITCHED_DOMAIN:-${HY2_DOMAIN:-}}"
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
    if openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes \
      -keyout /acme/shared/privkey.pem -out /acme/shared/fullchain.pem \
      -days 365 -subj "/CN=${cn_val}" -addext "$san_ext" >/dev/null 2>&1; then
      :
    else
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes \
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
    echo "[ERROR] 无 openssl，无法生成自签证书。请安装 openssl 后重试。"
  fi
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
# 2) 域名处理（可选，仅用于自签 CN/SAN）
# ===========================
if [ -n "${HY2_DOMAIN:-}" ]; then
  echo "[OK] 使用自定义域名（用于证书 CN/SAN）：${HY2_DOMAIN}"
else
  echo "[INFO] 未设置域名，将仅使用 IP SAN 自签证书"
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
# 5) 生成自签证书（含 IP SAN，域名可作为 CN/SAN）
# ===========================
USE_EXISTING_CERT=1
USE_CERT_PATH=""
USE_KEY_PATH=""
generate_self_signed_cert
apply_runtime_net_tuning
apply_extreme_loss_mitigation

# ===========================
# 6) 写 hysteria 配置（始终 TLS，自签证书）
# ===========================
mkdir -p /etc/hysteria
write_hysteria_main_config 1
SELF_SIGNED_USED=1
echo "[OK] 已写入 hysteria 配置（使用自签证书）"

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
RestartSec=1
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
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

# 启动额外端口实例（自签 TLS）
if [ -n "${HY2_PORTS:-}" ]; then
  # 通过封装函数写入各端口配置并启动实例
  start_additional_instances_with_tls
fi


# ===========================
# 8) 进程与端口检查（已简化，移除 ACME 等待/恢复）
# ===========================

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
URI="hysteria2://${PASS_ENC}@${SELECTED_IP}:${HY2_PORT}/?protocol=udp"
if [ "${DISABLE_OBFS}" != "1" ]; then
  URI="${URI}&obfs=salamander&obfs-password=${OBFS_ENC}"
fi
URI="${URI}&insecure=${INSECURE_VAL}&pinSHA256=${PIN_ENC}#${NAME_ENC}"

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
    P_URI="hysteria2://${P_PASS_ENC}@${SELECTED_IP}:${pt}/?protocol=udp"
    if [ "${DISABLE_OBFS}" != "1" ]; then
      P_URI="${P_URI}&obfs=salamander&obfs-password=${P_OBFS_ENC}"
    fi
    P_URI="${P_URI}&insecure=${INSECURE_VAL}&pinSHA256=${PIN_ENC}#${NAME_ENC}"
    echo "$pt -> $P_URI"
  done
  echo "======================================="
  echo
fi

# ===========================
# 10) 生成 ACL4SSR 规则的 Clash 订阅（整合所有端口到一个订阅）
# ===========================
mkdir -p "${CLASH_WEB_DIR}"
TARGET="${CLASH_OUT_PATH}"
TMPF="${TARGET}.tmp"

# 订阅头部（通用设置）
cat >"${TMPF}" <<EOF
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: ${CLASH_LOG_LEVEL}
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
EOF

# 生成每个端口的节点，name 使用端口号
IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
for pt in "${ports_all[@]}"; do
  if [ "$pt" = "$HY2_PORT" ]; then
    P_PASS="$HY2_PASS"
    P_OBFS="$OBFS_PASS"
  else
    P_PASS="${PASS_MAP[$pt]}"
    P_OBFS="${OBFS_MAP[$pt]}"
  fi

  # SNI 与证书校验
  SNI_LINE=""
  if [ "${DISABLE_SELF_SIGNED:-1}" -eq 0 ] || [ "${SELF_SIGNED_USED:-0}" -eq 1 ]; then
    SNI_LINE=""
  else
    if [ -n "${HY2_DOMAIN:-}" ]; then
      SNI_LINE="sni: ${HY2_DOMAIN}"
    fi
  fi
  VERIFY_LINE=""
  if [ "${SELF_SIGNED_USED:-0}" -eq 1 ] && [ "${DISABLE_SELF_SIGNED:-1}" -ne 0 ]; then
    VERIFY_LINE="skip-cert-verify: true"
  fi

  cat >>"${TMPF}" <<EOF
  - name: "${pt}"
    type: hysteria2
    server: ${SELECTED_IP}
    port: ${pt}
    password: ${P_PASS}
EOF
  if [ "${DISABLE_OBFS}" != "1" ]; then
    cat >>"${TMPF}" <<EOF
    obfs: salamander
    obfs-password: ${P_OBFS}
EOF
  fi
  [ -n "${SNI_LINE}" ] && echo "    ${SNI_LINE}" >>"${TMPF}"
  [ -n "${VERIFY_LINE}" ] && echo "    ${VERIFY_LINE}" >>"${TMPF}"
done

# 选择组包含所有端口名
echo >>"${TMPF}"
echo "proxy-groups:" >>"${TMPF}"
if [ "${ENABLE_URLTEST}" = "1" ]; then
  cat >>"${TMPF}" <<EOF
  - name: "自动选择"
    type: url-test
    url: ${CLASH_URLTEST_URL}
    interval: ${CLASH_URLTEST_INTERVAL}
    tolerance: ${CLASH_URLTEST_TOLERANCE}
    proxies:
EOF
  for pt in "${ports_all[@]}"; do
    echo "      - \"${pt}\"" >>"${TMPF}"
  done
fi

cat >>"${TMPF}" <<'EOF'
  - name: "🚀 节点选择"
    type: select
    proxies:
EOF
if [ "${ENABLE_URLTEST}" = "1" ]; then
  echo "      - \"自动选择\"" >>"${TMPF}"
fi
for pt in "${ports_all[@]}"; do
  echo "      - \"${pt}\"" >>"${TMPF}"
done
echo "      - DIRECT" >>"${TMPF}"

# 可选：故障转移组（fallback），与测速 URL/间隔一致
if [ "${ENABLE_FALLBACK}" = "1" ]; then
  cat >>"${TMPF}" <<EOF
  - name: "故障转移"
    type: fallback
    url: ${CLASH_URLTEST_URL}
    interval: ${CLASH_URLTEST_INTERVAL}
    proxies:
EOF
  for pt in "${ports_all[@]}"; do
    echo "      - \"${pt}\"" >>"${TMPF}"
  done
fi

# 规则
cat >>"${TMPF}" <<'EOF'

rules:
  - DOMAIN-SUFFIX,cn,DIRECT
  - DOMAIN-KEYWORD,baidu,DIRECT
  - DOMAIN-KEYWORD,taobao,DIRECT
  - DOMAIN-KEYWORD,qq,DIRECT
  - DOMAIN-KEYWORD,weixin,DIRECT
  - DOMAIN-KEYWORD,alipay,DIRECT
  - GEOIP,CN,DIRECT
EOF
if [ "${ENABLE_FALLBACK}" = "1" ]; then
  echo "  - MATCH,故障转移" >>"${TMPF}"
else
  echo "  - MATCH,🚀 节点选择" >>"${TMPF}"
fi

mv -f "${TMPF}" "${TARGET}"
echo "[OK] Clash 订阅已写入：${TARGET}"

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
echo
echo "提示：导入订阅后，在 Clash 客户端将 Proxy 组或 Stream/Game/VoIP 组指向你的节点并测试。"
