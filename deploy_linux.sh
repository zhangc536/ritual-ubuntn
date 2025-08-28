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
sudo apt-get remove --purge -y containerd containerd.io docker.io docker-compose || true
sudo apt-get autoremove -y
sudo apt-get clean

# 安装常规依赖
ubuntu_deps=(curl git nano jq lz4 make coreutils)
for dep in "${ubuntu_deps[@]}"; do
    if ! command -v $dep &>/dev/null; then
        info "📥 安装 $dep..."
        attempt=1
        while true; do
            if sudo apt-get install -y $dep; then
                info "✅ $dep 安装成功。"
                break
            else
                warn "⚠️ $dep 安装失败，第 $attempt 次重试..."
                sleep 3
                ((attempt++))
            fi
        done
    else
        info "✅ $dep 已安装，跳过安装。"
    fi
done

# 优先用官方脚本安装 Docker，失败则用 apt 安装 docker.io
if ! command -v docker &>/dev/null; then
    info "尝试用官方脚本安装 Docker..."
    if curl -fsSL https://get.docker.com | sudo bash; then
        info "✅ Docker 官方脚本安装成功"
    else
        warn "⚠️ 官方脚本安装失败，尝试用 apt 安装 docker.io（第 $attempt 次）"
        if sudo apt-get install -y docker.io; then
            info "✅ docker.io 安装成功"
            break
        fi
        sleep 10
        ((attempt++))
    done
else
    info "✅ Docker 已安装，版本：$(docker --version)"
fi

# 安装 docker-compose
if ! command -v docker-compose &>/dev/null; then
    sudo apt-get install -y docker-compose
fi

# 仅在 systemd 和 docker.service 存在时启动 docker 服务
if pidof systemd &>/dev/null && (systemctl list-unit-files | grep -q docker.service); then
    sudo systemctl enable docker
    sudo systemctl start docker
else
    info "未检测到 docker.service，跳过 systemctl 启动。"
fi

# 选择部署模式
echo "[6/15] 🛠️ 选择部署模式..." | tee -a "$log_file"
info "请选择 Infernet 节点的部署模式："
select yn in "是 (全新部署，清除并重装)" "否 (继续现有环境)" "直接部署合约" "更新配置并重启容器" "退出"; do
    case $yn in
        "是 (全新部署，清除并重装)")
            info "正在清除旧节点与数据..."
            if [ -d "$HOME/infernet-container-starter" ]; then
                cd "$HOME/infernet-container-starter"
                if ! docker-compose -f deploy/docker-compose.yaml down -v; then
                    warn "停止 Docker Compose 失败，继续清理..."
                fi
                cd "$HOME"
                if ! rm -rf infernet-container-starter; then
                    warn "删除 infernet-container-starter 失败，请检查权限。"
                else
                    info "已清除旧节点数据，即将开始全新部署。"
                fi
            else
                info "未找到旧节点数据，继续全新部署..."
            fi
            skip_to_deploy=false
            full_deploy=true
            break
            ;;
        "否 (继续现有环境)")
            info "检查现有部署环境..."
            if [ ! -d "$HOME/infernet-container-starter" ] || \
               [ ! -d "$HOME/infernet-container-starter/projects/hello-world/contracts" ] || \
               [ ! -f "$HOME/infernet-container-starter/projects/hello-world/contracts/Makefile" ] || \
               [ ! -f "$HOME/infernet-container-starter/projects/hello-world/contracts/script/Deploy.s.sol" ]; then
                error "现有环境不完整（缺少目录或文件），请选择 '是 (全新部署)' 或先运行完整部署。"
            fi
            skip_to_deploy=false
            full_deploy=false
            break
            ;;
        "直接部署合约")
            info "将直接执行合约部署步骤..."
            if [ ! -d "$HOME/infernet-container-starter/projects/hello-world/contracts" ] || \
               [ ! -f "$HOME/infernet-container-starter/projects/hello-world/contracts/Makefile" ] || \
               [ ! -f "$HOME/infernet-container-starter/projects/hello-world/contracts/script/Deploy.s.sol" ]; then
                error "合约目录或文件缺失，请先运行完整部署流程。"
            fi
            skip_to_deploy=true
            full_deploy=false
            break
            ;;
        "更新配置并重启容器")
            info "将更新配置文件并重启容器..."
            if [ ! -d "$HOME/infernet-container-starter" ] || [ ! -d "$HOME/infernet-container-starter/deploy" ]; then
                error "未找到部署目录，请先运行完整部署流程。"
            fi
            update_config_and_restart=true
            skip_to_deploy=false
            full_deploy=false
            break
            ;;
        "退出")
            warn "脚本已退出，未做任何更改。"
            exit 0
            ;;
    esac
done

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
            warn "无法连接到 RPC URL 或无效响应，第 $attempt 次重试..."
            sleep 10
            ((attempt++))
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
    
    # 检查并更新 docker-compose.yaml 中的 depends_on 设置
    info "检查并更新 docker-compose.yaml 中的 depends_on 设置..."
    if grep -q 'depends_on: \[ redis, infernet-anvil \]' docker-compose.yaml; then
        sed -i 's/depends_on: \[ redis, infernet-anvil \]/depends_on: [ redis ]/g' docker-compose.yaml
        cp docker-compose.yaml docker-compose.yaml.bak
        info "✅ docker-compose依赖已调整"
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
        info "启动容器（第$attempt次）..."
        if sudo docker compose up -d node redis fluentbit; then
            sleep 5 # 等待服务初始化
            info "✅ 容器启动成功"
            break
        else
            warn "启动失败，第$attempt次重试（10秒后）..."
            sleep 10 && ((attempt++))
        fi
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
    if ! command -v forge &> /dev/null; then
        info "Foundry 未安装，正在安装..."
        attempt=1
        while true; do
            if curl -L https://foundry.paradigm.xyz | bash; then
                echo 'export PATH="$HOME/.foundry/bin:$PATH"' >> ~/.bashrc
                source ~/.bashrc
                if foundryup; then
                    info "Foundry 安装成功，forge 版本：$(forge --version)"
                    break
                else
                    warn "Foundry 更新失败，第 $attempt 次重试..."
                fi
            else
                warn "Foundry 安装失败，第 $attempt 次重试..."
            fi
            sleep 10
            ((attempt++))
        done
    else
        info "Foundry 已安装，forge 版本：$(forge --version)"
    fi
else
    info "Foundry 未安装，forge 版本：$(forge --version)"
fi
