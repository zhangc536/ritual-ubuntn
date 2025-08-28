#!/bin/bash

set -e

# 定义日志函数，记录到文件和终端
log_file="$HOME/infernet-deployment.log"
info() { echo "ℹ️  $1" | tee -a "$log_file"; }
warn() { echo "⚠️  $1" | tee -a "$log_file"; }
error() { echo "❌ 错误：$1" | tee -a "$log_file"; exit 1; }

echo "======================================="
echo "🚀 Infernet Hello-World 一键部署工具 🚀"
echo "=======================================" | tee -a "$log_file"

# 配置文件路径，用于存储 RPC_URL 和 PRIVATE_KEY
config_file="$HOME/.infernet_config"

# 函数：加载或提示输入 RPC_URL 和 PRIVATE_KEY
load_or_prompt_config() {
    if [ -f "$config_file" ]; then
        info "检测到已保存的配置：$config_file"
        source "$config_file"
        info "当前 RPC_URL: $RPC_URL"
        info "当前 PRIVATE_KEY: ${PRIVATE_KEY:0:4}...（已隐藏后部分）"
        read -p "是否更新 RPC_URL 和 PRIVATE_KEY？(y/n): " update_config
        if [[ "$update_config" != "y" && "$update_config" != "Y" ]]; then
            return
        fi
    fi

    info "请输入以下信息以继续部署："
    read -p "请输入你的 RPC URL（Alchemy/Infura，例如 Base Mainnet 或 Sepolia）： " RPC_URL
    read -p "请输入你的私钥（0x 开头，不要泄露）： " PRIVATE_KEY

    # 输入校验
    if [[ -z "$RPC_URL" || -z "$PRIVATE_KEY" ]]; then
        error "RPC URL 和私钥不能为空。"
    fi
    if [[ ! "$RPC_URL" =~ ^https?://[a-zA-Z0-9.-]+ ]]; then
        error "无效的 RPC URL 格式。"
    fi
    if [[ ! "$PRIVATE_KEY" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
        error "无效的私钥格式（必须是 0x 开头的 64 位十六进制）。"
    fi

    # 保存到配置文件
    cat <<EOF > "$config_file"
RPC_URL="$RPC_URL"
PRIVATE_KEY="$PRIVATE_KEY"
EOF
    chmod 600 "$config_file" # 设置文件权限为仅用户可读写
    info "配置已保存至 $config_file"
}

# 检查 HOME 目录权限
if [ ! -w "$HOME" ]; then
    error "没有权限在 $HOME 目录下创建或删除文件，请检查权限或以适当用户运行脚本。"
fi

# 删除 containerd/containerd.io/docker 相关包，避免依赖冲突
info "[2/20] 清理Docker冲突包..."
sudo apt-get remove --purge -y docker.io docker-compose 2>/dev/null || true
sudo apt-get autoremove -y && sudo apt-get clean
info "✅ 冲突包清理完成"

# 3. 系统包索引更新（无限重试）
info "[1/20] 更新系统包索引..."
attempt=1
while true; do
    if sudo apt-get update -y; then
        info "✅ 系统包索引更新成功"
        break
    else
        warn "更新失败，第$attempt次重试（10秒后）..."
        sleep 10 && ((attempt++))
    fi
done

# 4. 安装基础依赖（无限重试）
info "[3/20] 安装基础依赖..."
ubuntu_deps=(curl git nano jq lz4 make coreutils lsof ca-certificates apt-transport-https software-properties-common)
for dep in "${ubuntu_deps[@]}"; do
    if command -v "$dep" &>/dev/null; then
        info "✅ $dep 已安装，跳过"
        continue
    fi
    attempt=1
    while true; do
        if sudo apt-get install -y "$dep"; then
            info "✅ $dep 安装成功"
            break
        else
            warn "$dep安装失败，第$attempt次重试（10秒后）..."
            sleep 10 && ((attempt++))
        fi
    done
done

# 5. Docker安装与配置（修复GPG路径+服务文件检查）
info "[4/20] 配置Docker环境..."
if ! command -v docker &>/dev/null || [ ! -f "/lib/systemd/system/docker.service" ]; then
    # 配置Docker官方GPG密钥（修复版）
    DOCKER_GPG="/etc/apt/keyrings/docker.gpg"
    sudo install -m 0755 -d /etc/apt/keyrings
    
    # 仅当文件不存在或为空时才下载，避免覆盖提示
    if [ ! -s "$DOCKER_GPG" ]; then
        info "添加Docker官方GPG密钥..."
        attempt=1
        while true; do
            if curl -fsSL --connect-timeout 15 --retry 3 https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o "$DOCKER_GPG"; then
                sudo chmod a+r "$DOCKER_GPG"
                info "✅ GPG密钥添加成功"
                break
            else
                warn "GPG密钥添加失败，第$attempt次重试（10秒后）..."
                attempt=$((attempt + 1))
                sleep 10
            fi
        done
    else
        info "Docker GPG密钥已存在，跳过下载"
    fi

    # 添加Docker仓库
    if [ ! -f "/etc/apt/sources.list.d/docker.list" ]; then
        info "添加Docker仓库..."
        echo "deb [arch=$(dpkg --print-architecture) signed-by=$DOCKER_GPG] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        # 刷新仓库（无限重试）
        attempt=1
        while true; do
            if sudo apt-get update -y; then
                info "✅ Docker仓库更新成功"
                break
            else
                warn "仓库更新失败，第$attempt次重试（10秒后）..."
                sleep 10 && ((attempt++))
            fi
        done
    fi

    # 安装Docker核心组件（无限重试）
    docker_pkgs=(docker-ce docker-ce-cli containerd.io docker-compose-plugin)
    for pkg in "${docker_pkgs[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            info "✅ $pkg 已安装，跳过"
            continue
        fi
        attempt=1
        while true; do
            if sudo apt-get install -y "$pkg"; then
                info "✅ $pkg 安装成功"
                break
            else
                warn "$pkg安装失败，第$attempt次重试（10秒后）..."
                sleep 10 && ((attempt++))
            fi
        done
    done

    # 手动创建Docker服务文件（防止安装缺失）
    if [ ! -f "/lib/systemd/system/docker.service" ]; then
        info "创建Docker服务文件..."
        sudo tee /lib/systemd/system/docker.service <<EOF_DOCKER_SERVICE
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target firewalld.service containerd.service
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
ExecReload=/bin/kill -s HUP \$MAINPID
TimeoutSec=0
RestartSec=2
Restart=always
StartLimitBurst=3
StartLimitInterval=60s
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
KillMode=process

[Install]
WantedBy=multi-user.target
EOF_DOCKER_SERVICE
        sudo systemctl daemon-reload
        info "✅ Docker服务文件创建完成"
    fi
    info "✅ Docker安装完成"
else
    info "✅ Docker已安装（版本：$(docker --version | awk '{print $3}' | cut -d',' -f1)）"
fi

# 启动Docker服务（无限重试）
info "[5/20] 启动Docker服务..."
if pidof systemd &>/dev/null; then
    attempt=1
    while true; do
        if sudo systemctl enable docker --now; then
            info "✅ Docker服务启动成功"
            break
        else
            warn "Docker服务启动失败，第$attempt次重试（10秒后）..."
            sleep 10 && ((attempt++))
        fi
    done
else
    info "非systemd系统，尝试直接启动dockerd..."
    sudo dockerd &
    sleep 5
    if pgrep dockerd &>/dev/null; then
        info "✅ Docker服务启动成功"
    else
        error "Docker服务启动失败，请手动检查"
    fi
fi

# 检查端口是否占用
info "检查端口占用..."
for port in 4000 6379 8545 5001; do
    if lsof -i :$port &> /dev/null; then
        info "端口 $port 被占用，尝试自动kill占用进程..."
        pids=$(lsof -t -i :$port)
        for pid in $pids; do
            if kill -9 $pid 2>/dev/null; then
                info "已kill进程 $pid (占用端口 $port)"
            else
                warn "无法kill进程 $pid (占用端口 $port)，请手动处理。"
            fi
        done
    else
        info "端口 $port 未被占用。"
    fi
done
info "Redis 端口 6379 被限制为本地访问，无需外部开放。"

# 添加部署模式选择菜单
info "请选择部署模式："
select deploy_mode in "全新部署" "继续现有环境" "直接部署合约" "更新配置并重启容器" "退出"; do
    case $deploy_mode in
        "全新部署")
            info "清除旧节点数据..."
            if [ -d "$HOME/infernet-container-starter" ]; then
                cd "$HOME/infernet-container-starter" && sudo docker compose -f deploy/docker-compose.yaml down -v 2>/dev/null || warn "停止容器失败，强制清理"
                cd "$HOME" && rm -rf infernet-container-starter || warn "删除旧目录失败，手动清理"
            fi
            skip_to_deploy=false && full_deploy=true
            break
            ;;
        "继续现有环境")
            if [ ! -d "$HOME/infernet-container-starter" ] || [ ! -d "$HOME/infernet-container-starter/projects/hello-world/contracts" ]; then
                error "现有环境不完整，请选择「全新部署」"
            fi
            skip_to_deploy=false && full_deploy=false
            break
            ;;
        "直接部署合约")
            if [ ! -d "$HOME/infernet-container-starter/projects/hello-world/contracts" ]; then
                error "合约目录缺失，请先执行「全新部署」"
            fi
            skip_to_deploy=true && full_deploy=false
            break
            ;;
        "更新配置并重启容器")
            if [ ! -d "$HOME/infernet-container-starter/deploy" ]; then
                error "部署目录缺失，请先执行「全新部署」"
            fi
            update_config_and_restart=true && skip_to_deploy=false && full_deploy=false
            break
            ;;
        "退出")
            warn "脚本已退出，未做任何更改"
            exit 0
            ;;
    esac
done

# 加载或提示输入配置（仅在全量部署或直接部署合约时需要）
if [ "$skip_to_deploy" = "true" ] || ([ "$yn" != "退出" ] && [ "$update_config_and_restart" != "true" ]); then
    echo "[8/15] 📝 加载或输入配置..." | tee -a "$log_file"
    load_or_prompt_config

    # 检查 RPC URL 连通性
    echo "[9/15] 🔍 测试 RPC URL 连通性..." | tee -a "$log_file"
    attempt=1
    while true; do
        chain_id=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_chainId","id":1}' "$RPC_URL" | jq -r '.result')
        if [ -n "$chain_id" ]; then
            info "检测到链 ID: $chain_id"
            break
        else
            warn "无法连接到 RPC URL 或无效响应，第 $attempt 次重试（10秒后）..."
            attempt=$((attempt + 1))
            sleep 10
        fi
    done
fi

# 更新配置并重启容器模式
if [ "$update_config_and_restart" = "true" ]; then
    echo "[8/8] 🔧 更新配置并重启容器..." | tee -a "$log_file"
    
    # 进入项目目录
    cd "$HOME/infernet-container-starter" || error "无法进入项目目录"
    
    # 更新配置文件
    info "正在更新配置文件..."
    if [ ! -f "deploy/config.json" ]; then
        error "未找到配置文件 deploy/config.json"
    fi
    
    # 备份原配置文件
    cp deploy/config.json deploy/config.json.backup.$(date +%Y%m%d_%H%M%S)
    info "已备份原配置文件"
    
    # 更新配置文件中的参数
    info "正在更新配置文件中的参数..."
    jq '.chain.snapshot_sync.batch_size = 10 | .chain.snapshot_sync.starting_sub_id = 262500 | .chain.snapshot_sync.retry_delay = 60' deploy/config.json > deploy/config.json.tmp
    mv deploy/config.json.tmp deploy/config.json
    
    info "已更新以下参数："
    info "- batch_size: 10"
    info "- starting_sub_id: 262500"
    info "- retry_delay: 60"
    
    # 进入deploy目录
    cd deploy || error "无法进入deploy目录"
    
    # 检查并更新 docker-compose.yml 中的 depends_on 设置
    info "检查并更新 docker-compose.yaml 中的 depends_on 设置..."
    if grep -q 'depends_on: \[ redis, infernet-anvil \]' docker-compose.yaml; then
        sed -i 's/depends_on: \[ redis, infernet-anvil \]/depends_on: [ redis ]/g' docker-compose.yaml
        info "已修改 depends_on 配置。备份文件保存在：docker-compose.yaml.bak"
    else
        info "depends_on 配置已正确，无需修改。"
    fi
    
    # 停止容器
    info "正在停止现有容器..."
    if docker-compose down; then
        info "容器已停止"
    else
        warn "停止容器时出现警告，继续执行..."
    fi
    
    # 启动指定服务：node、redis、fluentbit
    info "正在启动指定服务：node、redis、fluentbit..."
    attempt=1
    while true; do
        info "尝试启动容器 （第 $attempt 次）..."
        if docker-compose up node redis fluentbit; then
            info "容器启动成功"
            # 启动日志后台保存
            (docker logs -f infernet-node > "$HOME/infernet-deployment.log" 2>&1 &)
            break
        else
            warn "启动容器失败，第 $attempt 次重试（10秒后）..."
            sleep 10
        fi
        ((attempt++))
    done
    
    # 容器将在前台运行，脚本到此结束
    echo "[8/8] ✅ 配置更新完成！容器已在前台启动。" | tee -a "$log_file"
    info "容器正在前台运行，按 Ctrl+C 可停止容器"
    info "容器启动后，脚本将自动退出"
    exit 0
fi

# 直接部署合约模式：检查并安装依赖
if [ "$skip_to_deploy" = "true" ]; then
    # 检查 Foundry
    echo "[15/15] 🛠️ 安装 Foundry..." | tee -a "$log_file"
    if ! command -v forge &> /dev/null; then
        info "Foundry 未安装，正在安装..."
        attempt=1
        while true; do
            if curl -L https://foundry.paradigm.xyz | bash; then
                # 确保环境变量正确设置
                export PATH="$HOME/.foundry/bin:$PATH"
                # 重新加载 bashrc
                source ~/.bashrc 2>/dev/null || true
                # 等待一下让安装完成
                sleep 5
                # 尝试运行 foundryup
                if "$HOME/.foundry/bin/foundryup" 2>/dev/null || foundryup 2>/dev/null; then
                    # 再次确保环境变量加载
                    export PATH="$HOME/.foundry/bin:$PATH"
                    source ~/.bashrc 2>/dev/null || true
                    # 检查 forge 是否可用
                    if forge --version &>/dev/null; then
                        info "Foundry 安装成功，forge 版本：$(forge --version)"
                        break
                    else
                        warn "Foundry 安装完成但 forge 命令不可用，第 $attempt 次重试..."
                    fi
                else
                    warn "Foundry 更新失败，第 $attempt 次重试..."
                fi
            else
                warn "Foundry 安装失败，第 $attempt 次重试..."
            fi
            sleep 10
            attempt=$((attempt + 1))
        done
    else
        info "Foundry 已安装，forge 版本：$(forge --version)"
    fi
fi

echo "[9/15] 🧠 开始部署..." | tee -a "$log_file"

echo "[10/15] 📁 克隆仓库..." | tee -a "$log_file"
if [ "$full_deploy" = "true" ] || [ ! -d "$HOME/infernet-container-starter" ]; then
    if [ -d "$HOME/infernet-container-starter" ]; then
        info "目录 $HOME/infernet-container-starter 已存在，正在删除..."
        rm -rf "$HOME/infernet-container-starter" || error "删除 $HOME/infernet-container-starter 失败，请检查权限。"
    fi
    attempt=1
    while true; do
        info "尝试克隆仓库 （第 $attempt 次）..."
        if timeout 300 git clone https://github.com/ritual-net/infernet-container-starter "$HOME/infernet-container-starter" 2> git_clone_error.log; then
            if [ -d "$HOME/infernet-container-starter/deploy" ] && [ -d "$HOME/infernet-container-starter/projects/hello-world" ]; then
                info "仓库克隆成功，内容验证通过。"
                break
            else
                error "克隆的仓库内容不完整，缺少 deploy 或 projects/hello-world 目录。"
            fi
        else
            warn "克隆仓库失败，错误信息：$(cat git_clone_error.log)"
            warn "正在重试（10秒后）..."
            sleep 10
        fi
        ((attempt++))
    done
else
    info "使用现有目录 $HOME/infernet-container-starter 继续部署..."
    if [ ! -d "$HOME/infernet-container-starter/deploy" ] || \
       [ ! -d "$HOME/infernet-container-starter/projects/hello-world/contracts" ] || \
       [ ! -f "$HOME/infernet-container-starter/projects/hello-world/contracts/Makefile" ] || \
       [ ! -f "$HOME/infernet-container-starter/projects/hello-world/contracts/script/Deploy.s.sol" ]; then
        error "现有目录 $HOME/infernet-container-starter 不完整，缺少必要文件或目录，请选择全新部署。"
    fi
fi
cd "$(realpath -m "$HOME/infernet-container-starter")" || error "无法进入 $HOME/infernet-container-starter 目录，请检查目录是否存在或是否为有效符号链接。"
info "当前工作目录：$(pwd)"
ls -la . || warn "目录 $HOME/infernet-container-starter 为空或无法访问。"

echo "[11/15] 📦 拉取 hello-world 容器..." | tee -a "$log_file"
attempt=1
while true; do
    if curl -s --connect-timeout 5 https://registry-1.docker.io/ > /dev/null; then
        break
    else
        warn "无法连接到 Docker Hub，第 $attempt 次重试（10秒后）..."
        sleep 10
        attempt=$((attempt + 1))
    fi
done
attempt=1
while true;
do
    info "尝试拉取 ritualnetwork/hello-world-infernet:latest （第 $attempt 次）..."
    if docker pull ritualnetwork/hello-world-infernet:latest;
    then
        info "镜像拉取成功。"
        break
    else
        warn "拉取 hello-world 容器失败，第 $attempt 次重试（10秒后）..."
        sleep 10
        attempt=$((attempt + 1))
    fi
done

echo "[12/15] 🛠️ 写入项目配置 config.json..." | tee -a "$log_file"
if [ ! -d "$HOME/infernet-container-starter/deploy" ]; then
    mkdir -p "$HOME/infernet-container-starter/deploy" || error "创建 deploy 目录失败。"
fi
if [ -d "$HOME/infernet-container-starter/deploy/config.json" ]; then
    info "检测到 deploy/config.json 是一个目录，正在删除..."
    rm -rf "$HOME/infernet-container-starter/deploy/config.json" || error "删除 deploy/config.json 目录失败。"
fi
cat <<EOF > "$HOME/infernet-container-starter/deploy/config.json"
{
  "log_path": "infernet_node.log",
  "server": {
    "port": 4001,
    "rate_limit": { "num_requests": 100, "period": 100 }
  },
  "chain": {
    "enabled": true,
    "trail_head_blocks": 3,
    "rpc_url": "$RPC_URL",
    "registry_address": "0x3B1554f346DFe5c482Bb4BA31b880c1C18412170",
    "wallet": {
      "max_gas_limit": 4000000,
      "private_key": "$PRIVATE_KEY",
      "allowed_sim_errors": []
    },
    "snapshot_sync": {
      "sleep": 3,
      "batch_size": 10,
      "starting_sub_id": 262500,
      "sync_period": 30,
      "retry_delay": 60
    }
  },
  "startup_wait": 1.0,
  "redis": { "host": "redis", "port": 6379 },
  "forward_stats": true,
  "containers": [{
    "id": "hello-world",
    "image": "ritualnetwork/hello-world-infernet:latest",
    "external": true,
    "port": "5001",
    "allowed_delegate_addresses": [],
    "allowed_addresses": [],
    "allowed_ips": [],
    "command": "--bind=0.0.0.0:5001 --workers=2",
    "env": {},
    "volumes": [],
    "accepted_payments": {},
    "generates_proofs": false
  }]
}
EOF
if ! jq . "$HOME/infernet-container-starter/deploy/config.json" > /dev/null; then
    error "config.json 格式无效，请检查文件内容。"
fi
if ! cp "$HOME/infernet-container-starter/deploy/config.json" "$HOME/infernet-container-starter/projects/hello-world/container/config.json"; then
    error "复制 config.json 到 projects/hello-world/container 失败。"
fi

echo "[13/15] 🛠️ 更新 docker-compose.yaml..." | tee -a "$log_file"
cat <<'EOF' > "$HOME/infernet-container-starter/deploy/docker-compose.yaml"
services:
  node:
    image: ritualnetwork/infernet-node:1.4.0
    ports: [ "0.0.0.0:4001:4000" ]
    volumes:
      - ./config.json:/app/config.json
      - node-logs:/logs
      - /var/run/docker.sock:/var/run/docker.sock
    tty: true
    networks: [ network ]
    depends_on: [ redis ]
    restart: on-failure
    extra_hosts: [ "host.docker.internal:host-gateway" ]
    stop_grace_period: 1m
    container_name: infernet-node
  redis:
    image: redis:7.4.0
    ports: [ "6379:6379" ]
    volumes:
      - ./redis.conf:/usr/local/etc/redis/redis.conf
      - redis-data:/data
    networks: [ network ]
    restart: on-failure
    container_name: infernet-redis
  fluentbit:
    image: fluent/fluent-bit:3.1.4
    expose: [ "24224" ]
    environment: [ "FLUENTBIT_CONFIG_PATH=/fluent-bit/etc/fluent-bit.conf" ]
    volumes:
      - ./fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf
      - /var/log:/var/log:ro
    networks: [ network ]
    restart: on-failure
    container_name: infernet-fluentbit
networks:
  network:
volumes:
  node-logs:
  redis-data:
EOF

# 全新部署流程启动容器用后台模式
if [ "$full_deploy" = "true" ]; then
    echo "[14/15] 🐳 启动 Docker 容器..." | tee -a "$log_file"
    attempt=1
    while true; do
        info "尝试启动 Docker 容器 （第 $attempt 次）..."
        if docker-compose -f "$HOME/infernet-container-starter/deploy/docker-compose.yaml" up -d; then
            info "Docker 容器启动成功。"
            (docker logs -f infernet-node > "$HOME/infernet-deployment.log" 2>&1 &)
            break
        else
            warn "启动 Docker 容器失败，第 $attempt 次重试（10秒后）..."
            sleep 10
            attempt=$((attempt + 1))
        fi
    done
fi

echo "[15/15] 🛠️ 安装 Foundry..." | tee -a "$log_file"
if ! command -v forge &> /dev/null; then
    info "Foundry 未安装，正在安装..."
    attempt=1
    while true; do
        if curl -L https://foundry.paradigm.xyz | bash; then
            # 确保环境变量正确设置
            export PATH="$HOME/.foundry/bin:$PATH"
            # 重新加载 bashrc
            source ~/.bashrc 2>/dev/null || true
            # 等待一下让安装完成
            sleep 5
            # 尝试运行 foundryup
            if "$HOME/.foundry/bin/foundryup" 2>/dev/null || foundryup 2>/dev/null; then
                # 再次确保环境变量加载
                export PATH="$HOME/.foundry/bin:$PATH"
                source ~/.bashrc 2>/dev/null || true
                # 检查 forge 是否可用
                if forge --version &>/dev/null; then
                    info "Foundry 安装成功，forge 版本：$(forge --version)"
                    break
                else
                    warn "Foundry 安装完成但 forge 命令不可用，第 $attempt 次重试..."
                fi
            else
                warn "Foundry 更新失败，第 $attempt 次重试..."
            fi
        else
            warn "Foundry 安装失败，第 $attempt 次重试..."
        fi
        sleep 10
        attempt=$((attempt + 1))
    done
else
    info "Foundry 已安装，forge 版本：$(forge --version)"
fi

echo "[16/16] 📚 安装 Forge 库..." | tee -a "$log_file"
cd "$HOME/infernet-container-starter/projects/hello-world/contracts" || error "无法进入 $HOME/infernet-container-starter/projects/hello-world/contracts 目录"
if ! rm -rf lib/forge-std lib/infernet-sdk; then
    warn "清理旧 Forge 库失败，继续安装..."
fi
attempt=1
while true; do
    if forge install foundry-rs/forge-std; then
        info "forge-std 安装成功。"
        break
    else
        warn "安装 forge-std 失败，第 $attempt 次重试..."
        sleep 10
    fi
    ((attempt++))
done
attempt=1
while true; do
    if forge install ritual-net/infernet-sdk; then
        info "infernet-sdk 安装成功。"
        break
    else
        warn "安装 infernet-sdk 失败，第 $attempt 次重试..."
        sleep 10
    fi
    ((attempt++))
done

echo "[17/17] 🔧 写入部署脚本..." | tee -a "$log_file"
cat <<'EOF' > script/Deploy.s.sol
// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.13;
import {Script, console2} from "forge-std/Script.sol";
import {SaysGM} from "../src/SaysGM.sol";

contract Deploy is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        address deployerAddress = vm.addr(deployerPrivateKey);
        console2.log("Loaded deployer: ", deployerAddress);
        address registry = 0x3B1554f346DFe5c482Bb4BA31b880c1C18412170;
        SaysGM saysGm = new SaysGM(registry);
        console2.log("Deployed SaysGM: ", address(saysGm));
        vm.stopBroadcast();
    }
}
EOF

echo "[18/18] 📦 写入 Makefile..." | tee -a "$log_file"
cat <<'EOF' > "$HOME/infernet-container-starter/projects/hello-world/contracts/Makefile"
.PHONY: deploy
sender := $PRIVATE_KEY
RPC_URL := $RPC_URL
deploy:
    @PRIVATE_KEY=$(sender) forge script script/Deploy.s.sol:Deploy --broadcast --rpc-url $(RPC_URL)
EOF

echo "[19/19] 🚀 开始部署合约..." | tee -a "$log_file"
cd "$HOME/infernet-container-starter/projects/hello-world/contracts" || error "无法进入 $HOME/infernet-container-starter/projects/hello-world/contracts 目录"
attempt=1
while true; do
    info "尝试检查 RPC URL 连通性 （第 $attempt 次）..."
    if curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_chainId","id":1}' "$RPC_URL" | jq -e '.result' > /dev/null; then
        info "RPC URL 连通性检查成功。"
        break
    else
        warn "RPC URL 无法连接，第 $attempt 次重试（10秒后）..."
        sleep 10
    fi
    ((attempt++))
done
warn "请确保私钥有足够余额以支付 gas 费用。"
deploy_log=$(mktemp)
attempt=1
while true; do
    info "尝试部署合约 （第 $attempt 次）..."
    if PRIVATE_KEY="$PRIVATE_KEY" forge script script/Deploy.s.sol:Deploy --broadcast --rpc-url "$RPC_URL" > "$deploy_log" 2>&1; then
        info "🔺 合约部署成功！✅ 输出如下："
        cat "$deploy_log"
        break
    else
        warn "合约部署失败，详细信息如下：
$(cat "$deploy_log")
第 $attempt 次重试（10秒后）..."
        sleep 10
    fi
    ((attempt++))
done
contract_address=$(grep -i "Deployed SaysGM" "$deploy_log" | awk '{print $NF}' | head -n 1)
if [ -n "$contract_address" ] && [[ "$contract_address" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    info "部署的 SaysGM 合约地址：$contract_address"
    info "请保存此合约地址，用于后续调用！"
    call_contract_file="$HOME/infernet-container-starter/projects/hello-world/contracts/script/CallContract.s.sol"
    
    # 确保 script 目录存在
    mkdir -p "$HOME/infernet-container-starter/projects/hello-world/contracts/script" || error "无法创建 script 目录"
    
    # 创建或更新 CallContract.s.sol
    if [ ! -f "$call_contract_file" ]; then
        info "未找到 CallContract.s.sol，创建默认文件..."
        cat <<EOF > "$call_contract_file"
// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.13;
import {Script, console2} from "forge-std/Script.sol";
import {SaysGM} from "../src/SaysGM.sol";

contract CallContract is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        SaysGM saysGm = SaysGM($contract_address);
        saysGm.sayGM("Hello, Infernet!");
        console2.log("Called sayGM function");
        vm.stopBroadcast();
    }
}
EOF
        chmod 644 "$call_contract_file" || error "无法设置 CallContract.s.sol 文件权限"
        info "✅ 已成功创建 CallContract.s.sol，合约地址为 $contract_address"
    else
        info "找到现有 CallContract.s.sol，尝试更新合约地址..."
        # 备份现有文件
        cp "$call_contract_file" "${call_contract_file}.bak.$(date +%Y%m%d_%H%M%S)"
        # 尝试替换合约地址
        if grep -q "SaysGM(0x" "$call_contract_file"; then
            if sed -i "s|SaysGM(0x[0-9a-fA-F]\{40\})|SaysGM($contract_address)|g" "$call_contract_file"; then
                info "✅ 已成功更新 CallContract.s.sol 中的合约地址为 $contract_address"
            else
                error "更新 CallContract.s.sol 中的合约地址失败，请检查文件内容或权限：$call_contract_file"
            fi
        elif grep -q "ADDRESS_TO_GM" "$call_contract_file"; then
            if sed -i "s|ADDRESS_TO_GM|$contract_address|g" "$call_contract_file"; then
                info "✅ 已成功更新 CallContract.s.sol 中的占位符为 $contract_address"
            else
                error "更新 CallContract.s.sol 中的占位符失败，请检查文件内容或权限：$call_contract_file"
            fi
        else
            warn "未找到 SaysGM(0x...) 或 ADDRESS_TO_GM，尝试直接插入合约地址..."
            cat <<EOF > "$call_contract_file.tmp"
// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.13;
import {Script, console2} from "forge-std/Script.sol";
import {SaysGM} from "../src/SaysGM.sol";

contract CallContract is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        SaysGM saysGm = SaysGM($contract_address);
        saysGm.sayGM("Hello, Infernet!");
        console2.log("Called sayGM function");
        vm.stopBroadcast();
    }
}
EOF
            mv "$call_contract_file.tmp" "$call_contract_file" || error "无法覆盖 CallContract.s.sol 文件"
            chmod 644 "$call_contract_file" || error "无法设置 CallContract.s.sol 文件权限"
            info "✅ 已成功重写 CallContract.s.sol，合约地址为 $contract_address"
        fi
    fi
    
    # 验证合约地址是否正确更新
    if ! grep -q "SaysGM($contract_address)" "$call_contract_file"; then
        error "CallContract.s.sol 未正确更新合约地址，请检查文件：$call_contract_file"
    fi
    
    info "正在调用合约..."
    call_log=$(mktemp)
    attempt=1
    while true; do
        info "尝试调用合约 （第 $attempt 次）..."
        if PRIVATE_KEY="$PRIVATE_KEY" forge script "$call_contract_file" --broadcast --rpc-url "$RPC_URL" > "$call_log" 2>&1; then
            info "✅ 合约调用成功！输出如下："
            cat "$call_log"
            break
        else
            warn "合约调用失败，详细信息如下：
$(cat "$call_log")
第 $attempt 次重试（10秒后）..."
            sleep 10
        fi
        ((attempt++))
    done
    rm -f "$call_log"
else
    warn "未找到有效合约地址，请检查部署日志或手动验证。"
fi
rm -f "$deploy_log"

echo "[20/20] ✅ 部署完成！容器已在前台启动。" | tee -a "$log_file"
info "容器正在前台运行，按 Ctrl+C 可停止容器"
info "请检查日志：docker logs infernet-node"
info "下一步：可运行 'forge script script/CallContract.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY' 来再次调用合约。"

# 自动跳过 missing trie node 区块并重启节点
monitor_and_skip_trie_error() {
    LOG_FILE="$HOME/infernet-deployment.log"
    CONFIG_FILE="$HOME/infernet-container-starter/deploy/config.json"
    COMPOSE_DIR="$HOME/infernet-container-starter/deploy"
    LAST_BATCH_FILE="/tmp/ritual_last_batch.txt"

    info "启动 missing trie node 自动跳过守护进程..."
    while true; do
        line=$(grep "missing trie node" "$LOG_FILE" | tail -1)
        if [[ -n "$line" ]]; then
            batch=$(echo "$line" | grep -oE "batch=\\([0-9]+, [0-9]+\\)")
            if [[ $batch =~ ([0-9]+),\ ([0-9]+) ]]; then
                start=${BASH_REMATCH[1]}
                end=${BASH_REMATCH[2]}
                new_start=$((end + 1))
                if [[ -f "$LAST_BATCH_FILE" ]] && grep -q "$batch" "$LAST_BATCH_FILE"; then
                    sleep 30
                    continue
                fi
                echo "$batch" > "$LAST_BATCH_FILE"
                warn "检测到 missing trie node 错误区块，自动跳过到 $new_start 并重启节点..."
                jq ".chain.snapshot_sync.starting_sub_id = $new_start" "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
                cd "$COMPOSE_DIR"
                docker-compose restart node
                sleep 60
            fi
        fi
        sleep 30
    done
}

# 启动守护进程（后台运行）
monitor_and_skip_trie_error &

exit 0