#!/usr/bin/env bash
set -euo pipefail

############################
# 你的实际参数（已填入）
############################
CF_API_TOKEN="ZlH-iPvrBYMXgt2lpWLEF72ww_szK3HjBVNvHfx9"   # 仅 Zone:Read + DNS:Edit 权限
CF_ZONE_ID="7a825c1242fec406de06b79fcd9572d2"            # 该域名的 Zone ID（zhangcde.asia）
ROOT_DOMAIN="zhangcde.asia"                               # 你的主域
SUBDOMAIN="gs"                                            # 子域名（按你当前使用的 gs）
EMAIL="zhangc784512@gmail.com"                            # 证书邮箱
GH_TOKEN=""                                               # 可选：GitHub API Token（避免限额），无则留空
CF_LOCKDOWN=0                                             # 1=仅允许 Cloudflare 访问 80/443；0=不开启

############################
# 以下无需改动
############################
FQDN="${SUBDOMAIN}.${ROOT_DOMAIN}"

# 必须用 root 运行
if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo bash $0"
  exit 1
fi

echo "==> 部署下载站: https://${FQDN} （Cloudflare 橙云 + DNS-01）"

# 基础安装
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y nginx certbot python3-certbot-dns-cloudflare jq curl ufw

# 下载目录
mkdir -p /srv/downloads
chown -R www-data:www-data /srv/downloads
chmod -R 755 /srv/downloads

# 写入 Cloudflare 凭据（DNS-01）
install -m 600 -o root -g root /dev/null /root/cf.ini
cat >/root/cf.ini <<EOF
dns_cloudflare_api_token = ${CF_API_TOKEN}
EOF
chmod 600 /root/cf.ini

# 探测公网 IP（v4/v6）
get_ip() {
  local ver="$1"
  if [ "$ver" = "4" ]; then
    curl -4fsS https://api.ipify.org || curl -4fsS https://ifconfig.me || true
  else
    curl -6fsS https://api64.ipify.org || curl -6fsS https://ifconfig.me || true
  fi
}
IPV4="$(get_ip 4 || true)"
IPV6="$(get_ip 6 || true)"
echo "探测到 IPv4: ${IPV4:-无} ; IPv6: ${IPV6:-无}"

# Cloudflare API
api() { curl -fsS -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" "$@"; }

upsert_dns() {
  local type="$1" ip="$2"
  [ -z "$ip" ] && return 0
  echo "-> Upsert ${type} ${FQDN} = ${ip} (proxied=true)"
  local existing_id
  existing_id="$(api "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?type=${type}&name=${FQDN}" | jq -r '.result[0].id // empty')"
  local payload
  payload="$(jq -n --arg type "$type" --arg name "$FQDN" --arg content "$ip" '{type:$type,name:$name,content:$content,ttl:120,proxied:true}')"
  if [ -n "$existing_id" ]; then
    api -X PUT "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${existing_id}" --data "$payload" >/dev/null
  else
    api -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" --data "$payload" >/dev/null
  fi
}

[ -n "${IPV4:-}" ] && upsert_dns "A" "$IPV4" || true
[ -n "${IPV6:-}" ] && upsert_dns "AAAA" "$IPV6" || true

# 先放 HTTP 配置（证书前的占位）
cat >/etc/nginx/sites-available/${FQDN}.conf <<NGHTTP
server {
    listen 8071;
    listen [::]:8071;
    server_name ${FQDN};
    root /srv/downloads;
    index index.html;
    autoindex on;
    autoindex_exact_size off;
    autoindex_localtime on;

    types {
        application/x-apple-diskimage dmg;
        application/octet-stream pkg;
        application/zip zip;
    }

    add_header X-Content-Type-Options nosniff always;
    add_header Cache-Control "public, max-age=604800, immutable" always;
}
NGHTTP

ln -sf /etc/nginx/sites-available/${FQDN}.conf /etc/nginx/sites-enabled/${FQDN}.conf
nginx -t && systemctl reload nginx

# 申请证书（Cloudflare DNS-01；先等120秒，失败再等300秒）
obtain_cert() {
  local wait="$1"
  echo "==> 使用 DNS-01 签证书，传播等待 ${wait}s ..."
  certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials /root/cf.ini \
    --dns-cloudflare-propagation-seconds "${wait}" \
    -d "${FQDN}" \
    --agree-tos -m "${EMAIL}" --non-interactive
}

set +e
obtain_cert 120
RET=$?
if [ $RET -ne 0 ]; then
  echo "第一次签发失败，尝试将等待时间提高到 300 秒再试一次..."
  obtain_cert 300
  RET=$?
fi
set -e
if [ $RET -ne 0 ]; then
  echo "证书签发仍失败，请检查 /var/log/letsencrypt/letsencrypt.log"
  exit 1
fi

# 切换为 HTTPS
cat >/etc/nginx/sites-available/${FQDN}.conf <<'NGHTTPS'
server {
    listen 8071;
    listen [::]:8071;
    server_name FQDN_REPL;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name FQDN_REPL;

    root /srv/downloads;
    index index.html;
    autoindex on;
    autoindex_exact_size off;
    autoindex_localtime on;

    # TLS
    ssl_certificate     /etc/letsencrypt/live/FQDN_REPL/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/FQDN_REPL/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;

    # MIME
    types {
        application/x-apple-diskimage dmg;
        application/octet-stream pkg;
        application/zip zip;
    }

    add_header X-Content-Type-Options nosniff always;
    add_header Cache-Control "public, max-age=604800, immutable" always;
}
NGHTTPS

sed -i "s/FQDN_REPL/${FQDN}/g" /etc/nginx/sites-available/${FQDN}.conf
nginx -t && systemctl reload nginx

# UFW 基础放行
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw allow 8071/tcp  >/dev/null 2>&1 || true
ufw allow 443/tcp   >/dev/null 2>&1 || true
echo "提示：如使用 UFW，请确认规则后再执行：ufw enable（远程操作请谨慎）"

# 可选：仅允许 Cloudflare 访问 80/443
if [ "${CF_LOCKDOWN}" -eq 1 ]; then
  echo "==> 启用仅 Cloudflare 访问（8071/443）"
  curl -fsSL https://www.cloudflare.com/ips-v4 | xargs -I{} ufw allow proto tcp from {} to any port 443
  curl -fsSL https://www.cloudflare.com/ips-v6 | xargs -I{} ufw allow proto tcp from {} to any port 443
  curl -fsSL https://www.cloudflare.com/ips-v4 | xargs -I{} ufw allow proto tcp from {} to any port 8071
  curl -fsSL https://www.cloudflare.com/ips-v6 | xargs -I{} ufw allow proto tcp from {} to any port 8071
  ufw deny 443/tcp || true
  ufw deny 8071/tcp  || true
  echo "已添加 CF 限制规则。执行 'ufw status' 查看。"
fi

# 写入“只同步 Apple 芯片 DMG”的同步脚本
install -m 755 -o root -g root /dev/null /usr/local/bin/sync-verge-aarch64.sh
cat >/usr/local/bin/sync-verge-aarch64.sh <<'SYNC'
#!/usr/bin/env bash
set -euo pipefail

REPO="${REPO:-clash-verge-rev/clash-verge-rev}"
DEST="${DEST:-/srv/downloads}"
UA="sync-verge-aarch64/1.0"

mkdir -p "$DEST"

ghapi() {
  if [ -n "${GH_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: token ${GH_TOKEN}" -H "User-Agent: $UA" "$@"
  else
    curl -fsSL -H "User-Agent: $UA" "$@"
  fi
}

echo "==> 获取 ${REPO} 最新发布信息..."
JSON="$(ghapi "https://api.github.com/repos/${REPO}/releases/latest")" || {
  echo "获取 releases 失败：可能是 API 限额或网络问题。" >&2
  exit 1
}

# 仅选 aarch64/arm64 的 DMG
readarray -t LINES < <(echo "$JSON" | jq -r '.assets[]
  | select((.name|test("(?i)(aarch64|arm64)")) and (.name|endswith(".dmg")))
  | [.name, .browser_download_url] | @tsv')

if [ "${#LINES[@]}" -eq 0 ]; then
  echo "未找到 Apple 芯片（aarch64/arm64）DMG 资产，退出。" >&2
  exit 2
fi

BEST_LINE="$(printf '%s\n' "${LINES[@]}" | sort -V | tail -1)"
NAME="$(echo "$BEST_LINE" | cut -f1)"
URL="$(echo "$BEST_LINE" | cut -f2)"

OUT="${DEST}/${NAME}"
if [ -f "$OUT" ]; then
  echo "已存在: ${NAME}（跳过下载）"
else
  echo "-> 下载 ${NAME}"
  curl -fSL --retry 5 --retry-delay 2 -o "${OUT}.part" "$URL"
  mv "${OUT}.part" "$OUT"
fi

# 生成 sha256
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"
else
  shasum -a 256 "$OUT" | awk '{print $1}' > "${OUT}.sha256"
fi

# 最新软链 + 简洁页
cd "$DEST"
ln -sf "$NAME" Clash.Verge_latest_aarch64.dmg
cat > "$DEST/index.html" <<HTML
<!doctype html><meta charset="utf-8"><title>Clash Verge Rev · macOS（Apple 芯片）</title>
<style>body{font:16px/1.6 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:720px;margin:40px auto;padding:0 16px}h1{font-size:24px}</style>
<h1>Clash Verge Rev（Apple 芯片）</h1>
<p><a href="Clash.Verge_latest_aarch64.dmg">Clash.Verge_latest_aarch64.dmg</a> ·
   <a href="Clash.Verge_latest_aarch64.dmg.sha256">sha256</a></p>
<p><small>来源：GitHub Releases 的镜像，仅同步 Apple 芯片 DMG。</small></p>
HTML

echo "✅ 同步完成。"
SYNC

# 首次同步
echo "==> 首次同步 Apple 芯片 DMG..."
GH_TOKEN="${GH_TOKEN}" /usr/local/bin/sync-verge-aarch64.sh || true

# systemd 定时器（每天 02:20 / 14:20）
tee /etc/systemd/system/verge-sync-aarch64.service >/dev/null <<UNIT
[Unit]
Description=Sync Clash Verge Rev (Apple Silicon DMG only)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sync-verge-aarch64.sh
Environment=GH_TOKEN=${GH_TOKEN}
UNIT

tee /etc/systemd/system/verge-sync-aarch64.timer >/dev/null <<'UNIT'
[Unit]
Description=Run verge-sync-aarch64 twice daily

[Timer]
OnCalendar=*-*-* 02:20:00
OnCalendar=*-*-* 14:20:00
Persistent=true

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now verge-sync-aarch64.timer
systemctl start verge-sync-aarch64.service || true

# certbot 定时续期（系统自带 timer）
systemctl enable certbot.timer >/dev/null 2>&1 || true
systemctl start  certbot.timer >/dev/null 2>&1 || true

echo
echo "🎉 完成！现在可访问："
echo "  • 目录页   https://${FQDN}/"
echo "  • 最新 DMG https://${FQDN}/Clash.Verge_latest_aarch64.dmg"
echo "  • 校验值   https://${FQDN}/Clash.Verge_latest_aarch64.dmg.sha256"
[ "${CF_LOCKDOWN}" -eq 1 ] && echo "  • 已启用仅 Cloudflare 访问（8071/443）。查看：ufw status"
echo
