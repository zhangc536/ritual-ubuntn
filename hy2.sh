#!/usr/bin/env bash
set -euo pipefail

# ===========================
# Hysteria2 一键部署（含 ACME 与 429 检测/域名切换回退）
# ===========================

# 允许通过环境变量覆盖
HY2_PORT="${HY2_PORT:-8443}"
HY2_PORTS="${HY2_PORTS:-}" # 逗号分隔副端口，如 8444,8445
HY2_DOMAIN="${HY2_DOMAIN:-}"
NAME_TAG="${NAME_TAG:-hysteria2}"
SELECTED_IP="${SELECTED_IP:-}"
DISABLE_RATE_LIMIT_SWITCH="${DISABLE_RATE_LIMIT_SWITCH:-0}"

# 生成基本 IP 与域名
detect_ip() {
  if [ -n "$SELECTED_IP" ]; then
    echo "$SELECTED_IP"
    return 0
  fi
  local ip
  ip="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}')"
  if [ -z "$ip" ]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  echo "$ip"
}

SELECTED_IP="$(detect_ip)"
IP_DASH="${SELECTED_IP//./-}"

if [ -z "$HY2_DOMAIN" ]; then
  HY2_DOMAIN="${IP_DASH}.sslip.io"
fi

# ===========================
# 密码与端口列表
# ===========================
HY2_PASS="${HY2_PASS:-}"
OBFS_PASS="${OBFS_PASS:-}"
rand_hex() {
  local n="${1:-16}"; local out=""
  if command -v openssl >/dev/null 2>&1; then
    out="$(openssl rand -hex "$n" 2>/dev/null || true)"
  fi
  if [ -z "$out" ]; then
    out="$(date +%s%N | sha256sum | awk '{print $1}')"
    out="${out:0:$((n*2))}"
  fi
  echo "$out"
}
if [ -z "${HY2_PASS}" ]; then HY2_PASS="$(rand_hex 16)"; fi
if [ -z "${OBFS_PASS}" ]; then OBFS_PASS="$(rand_hex 8)"; fi

parse_port_list() {
  if [ -z "$HY2_PORTS" ]; then
    echo "$HY2_PORT"
  else
    echo "$HY2_PORT,$HY2_PORTS"
  fi
}

declare -A PASS_MAP
declare -A OBFS_MAP
gen_credentials_for_ports() {
  local list_csv="$1"; local p
  IFS=',' read -r -a ports <<<"$list_csv"
  for p in "${ports[@]}"; do
    if [ "$p" = "$HY2_PORT" ]; then
      PASS_MAP[$p]="$HY2_PASS"
      OBFS_MAP[$p]="$OBFS_PASS"
    else
      PASS_MAP[$p]="$(openssl rand -hex 16)"
      OBFS_MAP[$p]="$(openssl rand -hex 8)"
    fi
  done
}

PORT_LIST_CSV="$(parse_port_list)"
gen_credentials_for_ports "$PORT_LIST_CSV"

# ===========================
# 写配置
# ===========================
write_hysteria_main_config() {
  local use_tls="$1"
  mkdir -p /etc/hysteria /acme/autocert
  if [ "$use_tls" = "1" ]; then
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
  else
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
  type: http
  listenHost: 0.0.0.0
EOF
  fi
}

write_hysteria_config_for_port() {
  local port="$1"; local pass="$2"; local obfsp="$3"; local use_tls="$4"
  mkdir -p /etc/hysteria /acme/autocert
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
  type: http
  listenHost: 0.0.0.0
EOF
  fi
}

# ===========================
# systemd 管理
# ===========================
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

start_hysteria_instance() {
  local port="$1"
  systemctl enable --now "hysteria-server@${port}" || true
  if ! systemctl is-active --quiet "hysteria-server@${port}"; then
    echo "[WARN] hysteria-server@${port} 未处于 active 状态，输出最近日志以诊断："
    journalctl -u "hysteria-server@${port}" -n 50 --no-pager 2>/dev/null || true
  fi
}

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

check_udp_listening() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -lunp | grep -E ":${port}\b" || true
  elif command -v netstat >/dev/null 2>&1; then
    netstat -anu | grep -E "[\.:]${port}\b" || true
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iUDP:${port} || true
  else
    echo "[WARN] 缺少 ss/netstat/lsof，无法检查端口 ${port} 的监听状态"
  fi
}

# ===========================
# 证书导入与校验
# ===========================
USE_EXISTING_CERT=0
USE_CERT_PATH=""
USE_KEY_PATH=""

try_import_main_cert_shared() {
  if [ "$USE_EXISTING_CERT" -eq 1 ]; then
    return 0
  fi
  local domain="${SWITCHED_DOMAIN:-$HY2_DOMAIN}"
  local candidates=(
    "/acme/autocert" "/root/.cache/autocert" "/root/.acme.sh"
    "/var/lib/hysteria" "/etc/hysteria" "/var/cache/hysteria"
    "/etc/letsencrypt/live" "/etc/ssl" "/etc/nginx"
  )
  verify_cert_key_pair() {
    local cert="$1" key="$2" dom="$3"
    command -v openssl >/dev/null 2>&1 || return 0
    # 不临期
    openssl x509 -checkend 86400 -noout -in "$cert" >/dev/null 2>&1 || return 1
    # SAN/CN 域名匹配
    cert_domain_matches() {
      local c="$1" d="$2"; local san_entries=()
      mapfile -t san_entries < <(openssl x509 -noout -ext subjectAltName -in "$c" 2>/dev/null | grep -o -E 'DNS:[^,]+' | sed 's/^DNS://')
      for e in "${san_entries[@]}"; do [ "$e" = "$d" ] && return 0; done
      for e in "${san_entries[@]}"; do case "$e" in \*.*) local suffix="${e#*.}"; case "$d" in *."$suffix") return 0;; esac;; esac; done
      local cn; cn="$(openssl x509 -noout -subject -in "$c" 2>/dev/null | grep -o -E 'CN=[^/,]+' | head -n1 | sed 's/^CN=//')"
      [ -n "$cn" ] && [ "$cn" = "$d" ]
    }
    cert_domain_matches "$cert" "$dom" || return 1
    # 公钥哈希匹配（兼容 RSA/ECDSA）
    local cert_pub_hash key_pub_hash
    cert_pub_hash="$(openssl x509 -noout -pubkey -in "$cert" 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')"
    key_pub_hash="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')"
    [ -n "$cert_pub_hash" ] && [ -n "$key_pub_hash" ] && [ "$cert_pub_hash" = "$key_pub_hash" ]
  }
  local found_cert="" found_key=""
  for d in "${candidates[@]}"; do
    [ -d "$d" ] || continue
    mapfile -t certs < <(find "$d" -maxdepth 6 -type f \( -name "*fullchain*.pem" -o -name "*${domain}*.crt" -o -name "*${domain}*.cer" -o -name "*cert*.pem" -o -name "*.crt" -o -name "*.cer" \) 2>/dev/null)
    mapfile -t keys < <(find "$d" -maxdepth 6 -type f \( -name "*privkey*.pem" -o -name "*${domain}*.key" -o -name "*key*.pem" -o -name "*.key" \) 2>/dev/null)
    for c in "${certs[@]}"; do
      local base_dir="$(dirname "$c")"; local k_same
      k_same="$(find "$base_dir" -maxdepth 1 -type f \( -name "*privkey*.pem" -o -name "*${domain}*.key" -o -name "*key*.pem" -o -name "*.key" \) 2>/dev/null | head -n1)"
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
      mkdir -p /acme/shared
      local cert_dir; cert_dir="$(dirname "$found_cert")"
      if [ -f "$cert_dir/chain.pem" ]; then
        cat "$found_cert" "$cert_dir/chain.pem" > /acme/shared/fullchain.pem
      else
        cp -f "$found_cert" /acme/shared/fullchain.pem 2>/dev/null || cat "$found_cert" > /acme/shared/fullchain.pem
      fi
      cp -f "$found_key" /acme/shared/privkey.pem 2>/dev/null || cat "$found_key" > /acme/shared/privkey.pem
      USE_EXISTING_CERT=1
      USE_CERT_PATH="/acme/shared/fullchain.pem"
      USE_KEY_PATH="/acme/shared/privkey.pem"
      echo "[OK] 已从主服务导入证书到 /acme/shared（校验通过）"
      return 0
    fi
  done
  echo "[WARN] 未能定位主服务证书缓存文件"
  return 1
}

# ===========================
# 二进制安装（多镜像/重试/回退）
# ===========================
install_hysteria_binary() {
  echo "[*] 安装 hysteria ..."
  local arch asset bin url_main url_mirror url_version override
  arch="$(uname -m)"; bin="/usr/local/bin/hysteria"
  case "$arch" in
    x86_64|amd64) asset="hysteria-linux-amd64" ;;
    aarch64|arm64) asset="hysteria-linux-arm64" ;;
    armv7l|armv7) asset="hysteria-linux-arm" ;;
    i386|i686) asset="hysteria-linux-386" ;;
    *) asset="hysteria-linux-amd64" ;;
  esac
  url_main="https://github.com/apernet/hysteria/releases/latest/download/${asset}"
  url_mirror="https://ghproxy.com/https://github.com/apernet/hysteria/releases/latest/download/${asset}"
  override="${HYSTERIA_BIN_URL:-}"
  if [ -n "${HYSTERIA_VERSION:-}" ]; then
    url_version="https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VERSION}/${asset}"
  fi
  fetch() {
    local url="$1" out="$2"; [ -z "$url" ] && return 1
    if command -v curl >/dev/null 2>&1; then
      curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --ipv4 "$url" -o "$out" 2>/dev/null || return 1
    elif command -v wget >/dev/null 2>&1; then
      wget --tries=3 --timeout=15 -O "$out" "$url" >/dev/null 2>&1 || return 1
    else
      if command -v apt-get >/dev/null 2>&1; then apt-get update -y >/dev/null 2>&1 || true; apt-get install -y curl >/dev/null 2>&1 || true; fi
      command -v curl >/dev/null 2>&1 || return 1
      curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --ipv4 "$url" -o "$out" 2>/dev/null || return 1
    fi
    chmod +x "$out" 2>/dev/null || true
    "$out" -v >/dev/null 2>&1
  }
  if [ -n "$override" ] && fetch "$override" "$bin"; then echo "[OK] 覆盖 URL 安装 hysteria"; return 0; fi
  if [ -n "$url_version" ] && fetch "$url_version" "$bin"; then echo "[OK] 指定版本安装 hysteria"; return 0; fi
  if fetch "$url_main" "$bin"; then echo "[OK] GitHub latest 安装 hysteria"; return 0; fi
  if fetch "$url_mirror" "$bin"; then echo "[OK] ghproxy 镜像安装 hysteria"; return 0; fi
  if command -v go >/dev/null 2>&1; then
    echo "[INFO] 使用 go 回退安装"
    GO111MODULE=on go install -v github.com/apernet/hysteria@latest >/dev/null 2>&1 || true
    if [ -x "${HOME}/go/bin/hysteria" ]; then cp -f "${HOME}/go/bin/hysteria" "$bin" 2>/dev/null || true; chmod +x "$bin" || true; "$bin" -v >/dev/null 2>&1 && echo "[OK] go 安装成功" && return 0; fi
  fi
  echo "[ERROR] hysteria 二进制安装失败；可设置 HYSTERIA_BIN_URL 或手动放置到 $bin"
  return 1
}

command -v hysteria >/dev/null 2>&1 || install_hysteria_binary || true

# ===========================
# 主服务与 ACME 等待/429 切换
# ===========================
ACME_BASE="/acme"
USE_CERT_PATH=""
USE_KEY_PATH=""
if [ -d "$ACME_BASE" ]; then
  while IFS= read -r -d '' cert_dir; do
    FULLCHAIN="${cert_dir}/fullchain.pem"; PRIVKEY="${cert_dir}/privkey.pem"
    if [ -f "$FULLCHAIN" ] && [ -f "$PRIVKEY" ]; then
      USE_EXISTING_CERT=1; USE_CERT_PATH="$FULLCHAIN"; USE_KEY_PATH="$PRIVKEY"; echo "[OK] 检测到证书：$FULLCHAIN"; break
    fi
  done < <(find "$ACME_BASE" -type d -print0)
fi

if [ "$USE_EXISTING_CERT" -eq 0 ]; then
  echo "[INFO] /acme 下未找到证书，尝试从主服务缓存自动导入..."
  if try_import_main_cert_shared; then echo "[OK] 已自动导入主证书到 /acme/shared"; fi
fi

mkdir -p /etc/hysteria
if [ "$USE_EXISTING_CERT" -eq 1 ]; then
  write_hysteria_main_config 1
  echo "[OK] 已写入 hysteria 配置（使用 /acme 证书）"
else
  write_hysteria_main_config 0
  echo "[OK] 已写入 hysteria 配置（使用 ACME HTTP-01）"
fi

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
sleep 2
systemctl restart hysteria-server || true
if ! systemctl is-active --quiet hysteria-server; then
  echo "[WARN] hysteria-server 未处于 active 状态，输出最近日志以诊断："
  journalctl -u hysteria-server -n 80 --no-pager 2>/dev/null || true
fi

# 等待 ACME 完成并检测 429
ACME_OK=0; RATE_LIMITED=0; TRIES=0
if [ "$USE_EXISTING_CERT" -eq 0 ]; then
  echo "[*] 等待 hysteria ACME 证书申请完成（最多 60 秒）..."
  while [ $TRIES -lt 12 ]; do
    if journalctl -u hysteria-server --no-pager -n 200 | grep -E -iq "(certificate obtained successfully|acme_client.*authorization finalized|acme.*valid)"; then ACME_OK=1; break; fi
    if journalctl -u hysteria-server --no-pager -n 200 | grep -E -iq "(429|rate.?limit|too.?many.?requests|rateLimited)"; then RATE_LIMITED=1; echo "[WARN] 检测到 HTTP 429 速率限制错误"; break; fi
    sleep 5; TRIES=$((TRIES+1))
  done
fi

pick_alt_domain() {
  local ip="${SELECTED_IP}"; [ -z "$ip" ] && ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -z "$ip" ] && return 1
  local ip_dash="${ip//./-}"; local current_service=""; local dom resolved
  case "$HY2_DOMAIN" in *sslip.io) current_service="sslip.io" ;; *nip.io) current_service="nip.io" ;; *xip.io) current_service="xip.io" ;; esac
  local services=("sslip.io" "nip.io" "xip.io")
  for s in "${services[@]}"; do
    [ "$s" = "$current_service" ] && continue
    dom="${ip_dash}.${s}"; resolved=""
    if command -v getent >/dev/null 2>&1; then resolved="$(getent hosts "$dom" | awk '{print $1}' | head -n1)"; elif command -v nslookup >/dev/null 2>&1; then resolved="$(nslookup "$dom" 2>/dev/null | awk '/^Address: /{print $2; exit}')"; else resolved="$(ping -c1 -W2 "$dom" 2>/dev/null | sed -n 's/.*(\([0-9.]*\)).*/\1/p' | head -n1)"; fi
    if [ -n "$resolved" ] && [ "$resolved" = "$ip" ]; then echo "$dom"; return 0; fi
  done
  echo "${ip_dash}.nip.io"
  return 0
}

start_additional_instances_with_tls() {
  [ -n "${HY2_PORTS}" ] || return 0
  ensure_systemd_template
  IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
  for pt in "${ports_all[@]}"; do
    [ "$pt" = "$HY2_PORT" ] && continue
    write_hysteria_config_for_port "$pt" "${PASS_MAP[$pt]}" "${OBFS_MAP[$pt]}" "1"
    start_hysteria_instance "$pt"
  done
  ensure_udp_ports_open "$PORT_LIST_CSV"
}

start_additional_instances_with_acme_cache() {
  [ -n "${HY2_PORTS}" ] || return 0
  ensure_systemd_template
  IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
  for pt in "${ports_all[@]}"; do
    [ "$pt" = "$HY2_PORT" ] && continue
    write_hysteria_config_for_port "$pt" "${PASS_MAP[$pt]}" "${OBFS_MAP[$pt]}" "0"
    start_hysteria_instance "$pt"
  done
  ensure_udp_ports_open "$PORT_LIST_CSV"
}

if [ "$RATE_LIMITED" -eq 1 ] && [ "${DISABLE_RATE_LIMIT_SWITCH}" -eq 0 ]; then
  echo "[*] 由于 429 错误，尝试切换到备用域名服务..."
  SWITCHED_DOMAIN="$(pick_alt_domain)" || SWITCHED_DOMAIN=""
  if [ -n "$SWITCHED_DOMAIN" ]; then
    HY2_DOMAIN="$SWITCHED_DOMAIN"
    echo "[OK] 使用备用域名：$HY2_DOMAIN"
    if try_import_main_cert_shared; then
      write_hysteria_main_config 1; systemctl restart hysteria-server || true; echo "[OK] 主端口已切换为 TLS 证书运行"
      [ -n "${HY2_PORTS}" ] && start_additional_instances_with_tls
    else
      write_hysteria_main_config 0; systemctl restart hysteria-server || true; echo "[INFO] 主端口继续使用 ACME 配置运行（新域）"
      [ -n "${HY2_PORTS}" ] && start_additional_instances_with_acme_cache
    fi
  else
    echo "[WARN] 无法选择备用域名，保持现状"
  fi
fi

# 未发生 429 或未切换域名时，按现有策略启动副端口
if [ "$RATE_LIMITED" -eq 0 ]; then
  if [ "$USE_EXISTING_CERT" -eq 1 ]; then
    [ -n "${HY2_PORTS}" ] && start_additional_instances_with_tls
  else
    if [ "$ACME_OK" -eq 1 ]; then
      [ -n "${HY2_PORTS}" ] && start_additional_instances_with_acme_cache
    fi
  fi
fi

# 放行端口并检查监听
if [ -z "${HY2_PORTS}" ]; then ensure_udp_ports_open "$HY2_PORT"; else ensure_udp_ports_open "$PORT_LIST_CSV"; fi
echo "=== 监听检查（UDP/${HY2_PORT}) ==="; check_udp_listening "$HY2_PORT"
if [ -n "${HY2_PORTS}" ]; then
  echo "=== 监听检查（其他端口） ==="
  IFS=',' read -r -a ports_all <<<"$PORT_LIST_CSV"
  for pt in "${ports_all[@]}"; do [ "$pt" != "$HY2_PORT" ] && check_udp_listening "$pt"; done
fi

echo "[DONE] 部署完成：域名=${HY2_DOMAIN}，主端口=${HY2_PORT}"
