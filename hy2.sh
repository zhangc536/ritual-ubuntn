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
# 2) 生成域名（sslip.io 优先）
# ===========================
IP_DASH="${SELECTED_IP//./-}"
HY2_DOMAIN="${IP_DASH}.sslip.io"
RES_A="$(getent ahostsv4 "$HY2_DOMAIN" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
if [ -z "$RES_A" ] || [ "$RES_A" != "$SELECTED_IP" ]; then
  ALT="${IP_DASH}.nip.io"
  RES2="$(getent ahostsv4 "$ALT" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
  if [ -n "$RES2" ] && [ "$RES2" = "$SELECTED_IP" ]; then
    HY2_DOMAIN="$ALT"
  else
    echo "[WARN] sslip.io / nip.io 未解析到该 IP（${SELECTED_IP}）。"
    echo "       若要使用 ACME HTTP-01，请确保域名解析到本机且 80/tcp 可达。"
  fi
fi
echo "[OK] 使用域名/IP：${HY2_DOMAIN} -> ${SELECTED_IP}"

# ===========================
# 3) 安装 hysteria 二进制（若不存在）
# ===========================
if ! command -v hysteria >/dev/null 2>&1; then
  echo "[*] 安装 hysteria ... "
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
# 5) 检查 /acme 下所有子目录证书（优先使用）
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
  echo "[INFO] /acme 目录下未找到 fullchain/privkey 证书，将尝试 ACME HTTP-01（若需跳过请放证书到 /acme）"
fi

# ===========================
# 6) 写 Hysteria2 配置（使用现有证书或 ACME）
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
  key:
