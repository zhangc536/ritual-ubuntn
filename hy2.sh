#!/usr/bin/env bash
set -euo pipefail

# ===== 可改参数 =====
HY2_PORT="${HY2_PORT:-8443}"          # Hysteria2 UDP端口
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
  printf '%s' "$1" | sed -e 's/[\/&@]/\\&/g' -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g'
}

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
  echo "[INFO] /acme 下未找到证书，脚本将尝试 ACME HTTP-01（需 80/tcp 可达）"
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
        
        # 重新生成配置文件
        cat >/etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}

tls:
  cert: ${CERT_PATH}
  key: ${KEY_PATH}

auth:
  type: password
  password: ${HY2_PASS}

masquerade:
  type: proxy
  proxy:
    url: https://bing.com
    rewriteHost: true

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
  fi
else
  echo "[OK] 使用现有 /acme 证书，跳过 ACME 等待"
fi

echo "=== 监听检查（UDP/${HY2_PORT}) ==="
ss -lunp | grep -E ":${HY2_PORT}\b" || true

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
