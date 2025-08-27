#!/bin/bash

set -e

# 定义日志函数，记录到文件和终端
log_file="$HOME/infernet-deployment.log"
info() { echo "ℹ️  $1" | tee -a "$log_file"; }
warn() { echo "⚠️  $1" | tee -a "$log_file"; }
error() { echo "❌ 错误：$1" | tee -a "$log_file"; exit 1; }

echo "======================================="
echo "🚀 Infernet Hello-World 一键部署工具 (Ubuntu版) 🚀"
echo "=======================================" | tee -a "$log_file"

# 配置文件路径
config_file="$HOME/.infernet_config"

# 函数：加载或提示输入配置
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
    read -p "请输入你的 RPC URL： " RPC_URL
    read -p "请输入你的私钥（0x 开头）： " PRIVATE_KEY

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
    chmod 600 "$config_file"
    info "配置已保存至 $config_file"
}

# 检查 HOME 目录权限
if [ ! -w "$HOME" ]; then
    error "没有权限在 $HOME 目录下创建文件，请检查权限或以适当用户运行脚本。"
fi

# 更新系统包索引
info "更新系统包索引..."
sudo apt-get update -y

# 清理旧的容器相关包
sudo apt-get remove --purge -y containerd containerd.io docker.io docker-compose docker-compose-plugin || true
sudo apt-get autoremove -y
sudo apt-get clean

# 安装常规依赖（带预检查）
info "检查并安装基础依赖..."
ubuntu_deps=(curl git nano jq lz4 make coreutils lsof ca-certificates apt-transport-https software-properties-common)

for dep in "${ubuntu_deps[@]}"; do
    # 检查依赖是否已安装
    if command -v "$dep" &>/dev/null; then
        info "✅ $dep 已安装，跳过"
        continue
    fi
    
    # 未安装则进行安装
    info "📥 安装 $dep..."
    attempt=1
    max_attempts=3
    while [ $attempt -le $max_attempts ]; do
        if sudo apt-get install -y "$dep"; then
            info "✅ $dep 安装成功"
            break
        else
            warn "⚠️ $dep 安装失败，第 $attempt/$max_attempts 次重试..."
            if [ $attempt -eq $max_attempts ]; then
                error "$dep 安装失败，已达最大重试次数"
            fi
            sleep 3
            ((attempt++))
        fi
    done
done

# 检查并安装 Docker（带预检查）
info "检查 Docker 环境..."
if command -v docker &>/dev/null; then
    info "✅ Docker 已安装，版本：$(docker --version | awk '{print $3}' | cut -d',' -f1)"
else
    info "📥 开始安装 Docker..."
    
    # 添加 Docker 官方 GPG 密钥
    if [ ! -f "/usr/share/keyrings/docker-archive-keyring.gpg" ]; then
        info "添加 Docker 官方 GPG 密钥..."
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    else
        info "✅ Docker GPG 密钥已存在，跳过"
    fi
    
    # 添加 Docker 仓库
    if [ ! -f "/etc/apt/sources.list.d/docker.list" ]; then
        info "添加 Docker 仓库..."
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update -y
    else
        info "✅ Docker 仓库已存在，跳过"
    fi
    
    # 安装 Docker 组件
    docker_pkgs=(docker-ce docker-ce-cli containerd.io docker-compose-plugin)
    for pkg in "${docker_pkgs[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            info "✅ $pkg 已安装，跳过"
            continue
        fi
        
        info "安装 $pkg..."
        if ! sudo apt-get install -y "$pkg"; then
            error "$pkg 安装失败"
        fi
    done
    
    info "✅ Docker 安装完成"
fi

# 配置 Docker 服务
if pidof systemd &>/dev/null; then
    # 检查服务状态
    if ! systemctl is-active --quiet docker; then
        info "启动 Docker 服务..."
        sudo systemctl enable docker
        sudo systemctl start docker
    else
        info "✅ Docker 服务已运行"
    fi
    
    # 检查用户组
    if ! groups "$USER" | grep -q docker; then
        info "将当前用户添加到 docker 组..."
        sudo usermod -aG docker "$USER"
        info "用户已添加到 docker 组，注销并重新登录后生效（本次会话仍需 sudo）"
    else
        info "✅ 当前用户已在 docker 组中"
    fi
else
    info "未检测到 systemd，跳过服务管理"
fi

# 选择部署模式
echo "[6/15] 🛠️ 选择部署模式..." | tee -a "$log_file"
info "请选择 Infernet 节点的部署模式："
select yn in "是 (全新部署)" "否 (继续现有环境)" "直接部署合约" "更新配置并重启容器" "退出"; do
    case $yn in
        "是 (全新部署)")
            info "正在清除旧节点与数据..."
            if [ -d "$HOME/infernet-container-starter" ]; then
                cd "$HOME/infernet-container-starter"
                if ! docker compose -f deploy/docker-compose.yaml down -v; then
                    warn "停止 Docker Compose 失败，继续清理..."
                fi
                cd "$HOME"
                rm -rf infernet-container-starter || warn "删除旧目录失败，请检查权限"
                info "已清除旧节点数据"
            else
                info "未找到旧节点数据，开始全新部署..."
            fi
            skip_to_deploy=false
            full_deploy=true
            break
            ;;
        "否 (继续现有环境)")
            info "检查现有部署环境..."
            if [ ! -d "$HOME/infernet-container-starter" ] || \
               [ ! -d "$HOME/infernet-container-starter/projects/hello-world/contracts" ]; then
                error "现有环境不完整，请选择全新部署"
            fi
            skip_to_deploy=false
            full_deploy=false
            break
            ;;
        "直接部署合约")
            info "将直接执行合约部署步骤..."
            if [ ! -d "$HOME/infernet-container-starter/projects/hello-world/contracts" ]; then
                error "合约目录缺失，请先运行完整部署"
            fi
            skip_to_deploy=true
            full_deploy=false
            break
            ;;
        "更新配置并重启容器")
            info "将更新配置文件并重启容器..."
            if [ ! -d "$HOME/infernet-container-starter/deploy" ]; then
                error "未找到部署目录，请先运行完整部署"
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

# 检查端口占用
info "检查端口占用..."
for port in 4000 6379 8545 5001; do
    if lsof -i :"$port" &> /dev/null; then
        info "端口 $port 被占用，尝试自动关闭..."
        pids=$(lsof -t -i :"$port")
        for pid in $pids; do
            if sudo kill -9 "$pid" 2>/dev/null; then
                info "已关闭进程 $pid (占用端口 $port)"
            else
                warn "无法关闭进程 $pid，请手动处理"
            fi
        done
    else
        info "✅ 端口 $port 未被占用"
    fi
done

# 加载配置（按需）
if [ "$skip_to_deploy" = "true" ] || ([ "$yn" != "退出" ] && [ "$update_config_and_restart" != "true" ]); then
    echo "[8/15] 📝 加载或输入配置..." | tee -a "$log_file"
    load_or_prompt_config

    # 测试 RPC 连通性
    echo "[9/15] 🔍 测试 RPC 连接..." | tee -a "$log_file"
    max_attempts=5
    attempt=1
    while [ $attempt -le $max_attempts ]; do
        chain_id=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_chainId","id":1}' "$RPC_URL" | jq -r '.result')
        if [ -n "$chain_id" ]; then
            info "检测到链 ID: $chain_id"
            break
        else
            warn "RPC 连接失败，第 $attempt/$max_attempts 次重试..."
            if [ $attempt -eq $max_attempts ]; then
                error "RPC 连接失败，已达最大重试次数"
            fi
            sleep 10
        fi
        ((attempt++))
    done
fi

# 更新配置并重启容器模式
if [ "$update_config_and_restart" = "true" ]; then
    echo "[8/8] 🔧 更新配置并重启容器..." | tee -a "$log_file"
    
    cd "$HOME/infernet-container-starter" || error "无法进入项目目录"
    
    # 备份并更新配置
    if [ -f "deploy/config.json" ]; then
        cp deploy/config.json "deploy/config.json.backup.$(date +%Y%m%d_%H%M%S)"
        info "已备份配置文件"
        
        jq '.chain.snapshot_sync.batch_size = 10 | .chain.snapshot_sync.starting_sub_id = 262500 | .chain.snapshot_sync.retry_delay = 60' deploy/config.json > deploy/config.json.tmp
        mv deploy/config.json.tmp deploy/config.json
        info "已更新配置参数"
    else
        error "未找到配置文件 deploy/config.json"
    fi
    
    # 调整 docker-compose 配置
    cd deploy || error "无法进入 deploy 目录"
    if grep -q 'depends_on: \[ redis, infernet-anvil \]' docker-compose.yaml; then
        sed -i 's/depends_on: \[ redis, infernet-anvil \]/depends_on: [ redis ]/g' docker-compose.yaml
        cp docker-compose.yaml docker-compose.yaml.bak
        info "已修改 depends_on 配置"
    else
        info "✅ docker-compose 配置已正确"
    fi
    
    # 重启容器
    info "停止现有容器..."
    sudo docker compose down || warn "停止容器时出现警告"
    
    info "启动服务：node、redis、fluentbit..."
    attempt=1
    max_attempts=5
    while [ $attempt -le $max_attempts ]; do
        if sudo docker compose up node redis fluentbit; then
            info "容器启动成功"
            (sudo docker logs -f infernet-node >> "$log_file" 2>&1 &)
            break
        else
            warn "启动失败，第 $attempt/$max_attempts 次重试..."
            if [ $attempt -eq $max_attempts ]; then
                error "启动容器失败，已达最大重试次数"
            fi
            sleep 10
        fi
        ((attempt++))
    done
    
    echo "[8/8] ✅ 配置更新完成！容器已启动" | tee -a "$log_file"
    exit 0
fi

# 检查并安装 Foundry（合约部署需要）
if [ "$skip_to_deploy" = "true" ]; then
    info "检查 Foundry 环境..."
    if command -v forge &> /dev/null; then
        info "✅ Foundry 已安装，版本：$(forge --version | head -n1 | awk '{print $2}')"
    else
        info "📥 安装 Foundry..."
        max_attempts=3
        attempt=1
        while [ $attempt -le $max_attempts ]; do
            if curl -L https://foundry.paradigm.xyz | bash; then
                echo 'export PATH="$HOME/.foundry/bin:$PATH"' >> ~/.bashrc
                source ~/.bashrc
                if foundryup; then
                    info "✅ Foundry 安装成功"
                    break
                else
                    warn "Foundry 更新失败，重试..."
                fi
            else
                warn "Foundry 安装失败，重试..."
            fi
            if [ $attempt -eq $max_attempts ]; then
                error "Foundry 安装失败"
            fi
            sleep 10
            ((attempt++))
        done
    fi
fi

echo "[9/15] 🧠 开始部署..." | tee -a "$log_file"

# 克隆仓库（按需）
echo "[10/15] 📁 处理项目仓库..." | tee -a "$log_file"
if [ "$full_deploy" = "true" ] || [ ! -d "$HOME/infernet-container-starter" ]; then
    if [ -d "$HOME/infernet-container-starter" ]; then
        rm -rf "$HOME/infernet-container-starter" || error "删除旧目录失败"
    fi
    
    max_attempts=3
    attempt=1
    while [ $attempt -le $max_attempts ]; do
        info "克隆仓库（第 $attempt 次）..."
        if git clone https://github.com/ritual-net/infernet-container-starter "$HOME/infernet-container-starter"; then
            if [ -d "$HOME/infernet-container-starter/deploy" ]; then
                info "✅ 仓库克隆成功"
                break
            else
                error "仓库内容不完整"
            fi
        else
            warn "克隆失败，重试..."
            if [ $attempt -eq $max_attempts ]; then
                error "克隆仓库失败"
            fi
            sleep 10
            ((attempt++))
        fi
    done
else
    info "✅ 使用现有项目目录"
fi

cd "$HOME/infernet-container-starter" || error "无法进入项目目录"

# 拉取容器镜像（带检查）
echo "[11/15] 📦 处理容器镜像..." | tee -a "$log_file"
image="ritualnetwork/hello-world-infernet:latest"
if sudo docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "$image"; then
    info "✅ $image 镜像已存在，跳过拉取"
else
    max_attempts=3
    attempt=1
    while [ $attempt -le $max_attempts ]; do
        info "拉取 $image（第 $attempt 次）..."
        if sudo docker pull "$image"; then
            info "✅ 镜像拉取成功"
            break
        else
            warn "拉取失败，重试..."
            if [ $attempt -eq $max_attempts ]; then
                error "拉取镜像失败"
            fi
            sleep 10
            ((attempt++))
        fi
    done
fi

# 生成配置文件
echo "[12/15] 🛠️ 生成配置文件..." | tee -a "$log_file"
mkdir -p deploy || error "创建 deploy 目录失败"
cat <<EOF > "deploy/config.json"
{
  "log_path": "infernet_node.log",
  "chain": {
    "rpc_url": "$RPC_URL",
    "private_key": "$PRIVATE_KEY",
    "check_interval": 5,
    "snapshot_sync": {
      "enabled": true,
      "batch_size": 10,
      "starting_sub_id": 262500,
      "retry_delay": 60
    }
  },
  "server": {
    "host": "0.0.0.0",
    "port": 4000
  },
  "worker": {
    "concurrency": 10
  },
  "redis": {
    "host": "redis",
    "port": 6379
  }
}
EOF
info "✅ 配置文件生成完成"

echo "[13/15] 🚀 启动容器服务..." | tee -a "$log_file"
cd deploy || error "无法进入 deploy 目录"

# 调整 docker-compose 配置（如果需要）
if grep -q 'depends_on: \[ redis, infernet-anvil \]' docker-compose.yaml; then
    sed -i 's/depends_on: \[ redis, infernet-anvil \]/depends_on: [ redis ]/g' docker-compose.yaml
    cp docker-compose.yaml docker-compose.yaml.bak
    info "已调整 docker-compose 依赖配置"
fi

# 启动服务
attempt=1
max_attempts=3
while [ $attempt -le $max_attempts ]; do
    info "启动容器（第 $attempt 次）..."
    if sudo docker compose up -d; then
        info "✅ 容器启动成功"
        sleep 5  # 等待服务初始化
        break
    else
        warn "启动失败，重试..."
        if [ $attempt -eq $max_attempts ]; then
            error "启动容器失败"
        fi
        sleep 10
        ((attempt++))
    fi
done

# 部署合约
echo "[14/15] 📜 部署合约..." | tee -a "$log_file"
cd "$HOME/infernet-container-starter/projects/hello-world/contracts" || error "无法进入合约目录"

# 安装合约依赖
if [ ! -d "lib" ]; then
    info "安装合约依赖..."
    forge install foundry-rs/forge-std OpenZeppelin/openzeppelin-contracts || error "安装合约依赖失败"
else
    info "✅ 合约依赖已存在，跳过安装"
fi

# 执行部署
info "开始部署合约..."
if forge script script/Deploy.s.sol:Deploy --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast --verify; then
    info "✅ 合约部署成功"
else
    error "合约部署失败"
fi

echo "[15/15] ✅ 全部部署完成！" | tee -a "$log_file"
info "部署日志已保存至 $log_file"
info "节点状态可通过: sudo docker compose -f $HOME/infernet-container-starter/deploy/docker-compose.yaml ps 查看"
info "节点日志可通过: sudo docker logs -f infernet-node 查看"
