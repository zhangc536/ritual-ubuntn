#!/bin/bash
set -e

# 日志配置：同时输出到终端和文件
log_file="$HOME/infernet-deployment.log"
info() { echo "ℹ️  $1" | tee -a "$log_file"; }
warn() { echo "⚠️  $1" | tee -a "$log_file"; }
error() { echo "❌ 错误：$1" | tee -a "$log_file"; exit 1; }

# 脚本启动提示
echo "======================================="
echo "🚀 Infernet Hello-World 一键部署工具 (Ubuntu版) 🚀"
echo "=======================================" | tee -a "$log_file"

# 配置文件路径
config_file="$HOME/.infernet_config"

# 1. 加载/输入配置（含格式校验）
load_or_prompt_config() {
    if [ -f "$config_file" ]; then
        info "检测到已保存配置：$config_file"
        source "$config_file"
        info "当前 RPC_URL: $RPC_URL"
        info "当前 PRIVATE_KEY: ${PRIVATE_KEY:0:4}...（已隐藏后部分）"
        read -p "是否更新配置？(y/n): " update_config
        [[ "$update_config" != "y" && "$update_config" != "Y" ]] && return
    fi

    info "请输入部署信息："
    read -p "RPC URL（https开头）： " RPC_URL
    read -p "私钥（0x开头64位十六进制）： " PRIVATE_KEY

    # 输入校验（不可重试错误，直接退出）
    [[ -z "$RPC_URL" || -z "$PRIVATE_KEY" ]] && error "RPC URL/私钥不能为空"
    [[ ! "$RPC_URL" =~ ^https?://[a-zA-Z0-9.-]+ ]] && error "RPC URL格式无效"
    [[ ! "$PRIVATE_KEY" =~ ^0x[0-9a-fA-F]{64}$ ]] && error "私钥格式无效（需0x开头64位十六进制）"

    # 保存配置（权限600防泄露）
    cat <<EOF > "$config_file"
RPC_URL="$RPC_URL"
PRIVATE_KEY="$PRIVATE_KEY"
EOF
    chmod 600 "$config_file"
    info "配置已保存至 $config_file"
}

# 2. 前置权限检查
if [ ! -w "$HOME" ]; then
    error "无$HOME目录写入权限，请切换用户或调整权限"
fi

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

# 4. 清理Docker冲突包（仅清理旧版，保留核心组件）
info "[2/20] 清理Docker冲突包..."
sudo apt-get remove --purge -y docker.io docker-compose 2>/dev/null || true
sudo apt-get autoremove -y && sudo apt-get clean
info "✅ 冲突包清理完成"

# 5. 安装基础依赖（无限重试）
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

# 6. Docker安装与配置（修复GPG路径+服务文件检查）
info "[4/20] 配置Docker环境..."
if ! command -v docker &>/dev/null || [ ! -f "/lib/systemd/system/docker.service" ]; then
    # 配置Docker官方GPG密钥（新版路径：/etc/apt/keyrings）
    sudo install -m 0755 -d /etc/apt/keyrings
    if [ ! -f "/etc/apt/keyrings/docker.gpg" ]; then
        info "添加Docker官方GPG密钥..."
        attempt=1
        while true; do
            if curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg; then
                sudo chmod a+r /etc/apt/keyrings/docker.gpg
                info "✅ GPG密钥添加成功"
                break
            else
                warn "GPG密钥添加失败，第$attempt次重试（10秒后）..."
                sleep 10 && ((attempt++))
            fi
        done
    fi

    # 添加Docker仓库
    if [ ! -f "/etc/apt/sources.list.d/docker.list" ]; then
        info "添加Docker仓库..."
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
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
        sudo tee /lib/systemd/system/docker.service <<EOF
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
EOF
        sudo systemctl daemon-reload
        info "✅ Docker服务文件创建完成"
    fi
    info "✅ Docker安装完成"
else
    info "✅ Docker已安装（版本：$(docker --version | awk '{print $3}' | cut -d',' -f1)）"
fi

# 7. 启动Docker服务（无限重试）
info "[5/20] 启动Docker服务..."
if pidof systemd &>/dev/null; then
    attempt=1
    while true; do
        sudo systemctl enable docker
        if sudo systemctl start docker; then
            info "✅ Docker服务启动成功"
            break
        else
            warn "Docker启动失败，第$attempt次重试（10秒后）..."
            sudo chmod 666 /var/run/docker.sock 2>/dev/null # 修复权限
            sleep 10 && ((attempt++))
        fi
    done

    # 添加用户到docker组
    if ! groups "$USER" | grep -q docker; then
        sudo usermod -aG docker "$USER"
        info "✅ 当前用户已加入docker组（注销重登后生效，本次需sudo）"
    else
        info "✅ 当前用户已在docker组"
    fi
else
    info "未检测到systemd，跳过Docker服务管理"
fi

# 8. 选择部署模式
echo "[6/20] 选择部署模式..." | tee -a "$log_file"
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

# 9. 端口占用检查与清理
info "[7/20] 检查端口占用（4000/6379/8545/5001）..."
for port in 4000 6379 8545 5001; do
    if lsof -i :"$port" &>/dev/null; then
        info "端口$port被占用，尝试关闭..."
        pids=$(lsof -t -i :"$port")
        for pid in $pids; do
            sudo kill -9 "$pid" 2>/dev/null && info "已关闭进程$pid（占用$port）" || warn "无法关闭进程$pid，请手动处理"
        done
    else
        info "✅ 端口$port未占用"
    fi
done

# 10. 加载配置（按需）与RPC连通性测试
if [ "$skip_to_deploy" = "true" ] || [ "$update_config_and_restart" != "true" ]; then
    echo "[8/20] 加载部署配置..." | tee -a "$log_file"
    load_or_prompt_config

    # RPC连通性测试（无限重试）
    echo "[9/20] 测试RPC连接..." | tee -a "$log_file"
    attempt=1
    while true; do
        chain_id=$(curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_chainId","id":1}' "$RPC_URL" | jq -r '.result')
        if [ -n "$chain_id" ]; then
            info "✅ 检测到链ID：$chain_id"
            break
        else
            warn "RPC连接失败，第$attempt次重试（10秒后）..."
            sleep 10 && ((attempt++))
        fi
    done
fi

# 11. 「更新配置并重启容器」模式处理
if [ "$update_config_and_restart" = "true" ]; then
    echo "[8/8] 更新配置并重启容器..." | tee -a "$log_file"
    cd "$HOME/infernet-container-starter" || error "无法进入项目目录"

    # 备份并更新config.json
    if [ -f "deploy/config.json" ]; then
        cp deploy/config.json "deploy/config.json.backup.$(date +%Y%m%d_%H%M%S)"
        jq '.chain.snapshot_sync.batch_size = 10 | .chain.snapshot_sync.starting_sub_id = 262500 | .chain.snapshot_sync.retry_delay = 60' deploy/config.json > deploy/config.json.tmp
        mv deploy/config.json.tmp deploy/config.json
        info "✅ 配置文件已更新并备份"
    else
        error "未找到deploy/config.json"
    end

    # 调整docker-compose依赖
    cd deploy || error "无法进入deploy目录"
    if grep -q 'depends_on: \[ redis, infernet-anvil \]' docker-compose.yaml; then
        sed -i 's/depends_on: \[ redis, infernet-anvil \]/depends_on: [ redis ]/g' docker-compose.yaml
        cp docker-compose.yaml docker-compose.yaml.bak
        info "✅ docker-compose依赖已调整"
    fi

    # 重启容器（无限重试）
    info "停止现有容器..."
    sudo docker compose down 2>/dev/null || warn "停止容器出现警告"
    
    info "启动node/redis/fluentbit..."
    attempt=1
    while true; do
        if sudo docker compose up node redis fluentbit; then
            (sudo docker logs -f infernet-node >> "$log_file" 2>&1 &)
            info "✅ 容器重启成功"
            break
        else
            warn "启动失败，第$attempt次重试（10秒后）..."
            sleep 10 && ((attempt++))
        fi
    done

    echo "[8/8] ✅ 配置更新完成！" | tee -a "$log_file"
    exit 0
fi

# 12. 安装Foundry（按官方脚本逻辑，无限重试）
echo "[10/20] 安装Foundry..." | tee -a "$log_file"
if ! command -v forge &>/dev/null; then
    info "Foundry未安装，开始安装..."
    attempt=1
    while true; do
        if curl -L https://foundry.paradigm.xyz | bash; then
            # 加载环境变量（确保forge可用）
            export PATH="$HOME/.foundry/bin:$PATH"
            source ~/.bashrc 2>/dev/null || true
            sleep 5

            # 运行foundryup（无限重试）
            if "$HOME/.foundry/bin/foundryup" 2>/dev/null || foundryup 2>/dev/null; then
                export PATH="$HOME/.foundry/bin:$PATH"
                source ~/.bashrc 2>/dev/null || true
                if forge --version &>/dev/null; then
                    info "✅ Foundry安装成功（版本：$(forge --version | head -n1 | awk '{print $2}')）"
                    break
                else
                    warn "Foundry安装完成但forge不可用，第$attempt次重试（10秒后）..."
                fi
            else
                warn "foundryup执行失败，第$attempt次重试（10秒后）..."
            fi
        else
            warn "Foundry安装脚本执行失败，第$attempt次重试（10秒后）..."
        fi
        sleep 10 && ((attempt++))
    done
else
    info "✅ Foundry已安装（版本：$(forge --version | head -n1 | awk '{print $2}')）"
fi

# 13. 克隆项目仓库（无限重试）
echo "[11/20] 处理项目仓库..." | tee -a "$log_file"
if [ "$full_deploy" = "true" ] || [ ! -d "$HOME/infernet-container-starter" ]; then
    [ -d "$HOME/infernet-container-starter" ] && rm -rf "$HOME/infernet-container-starter" || true
    attempt=1
    while true; do
        info "克隆仓库（第$attempt次）..."
        if git clone https://github.com/ritual-net/infernet-container-starter "$HOME/infernet-container-starter"; then
            if [ -d "$HOME/infernet-container-starter/deploy" ]; then
                info "✅ 仓库克隆成功"
                break
            else
                error "仓库内容不完整，重新克隆"
            fi
        else
            warn "克隆失败，第$attempt次重试（10秒后）..."
            sleep 10 && ((attempt++))
        fi
    done
else
    info "✅ 使用现有项目目录"
fi
cd "$HOME/infernet-container-starter" || error "无法进入项目目录"

# 14. 拉取容器镜像（无限重试）
echo "[12/20] 拉取Hello-World镜像..." | tee -a "$log_file"
image="ritualnetwork/hello-world-infernet:latest"
if sudo docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "$image"; then
    info "✅ $image 镜像已存在，跳过拉取"
else
    attempt=1
    while true; do
        info "拉取$image（第$attempt次）..."
        if sudo docker pull "$image"; then
            info "✅ 镜像拉取成功"
            break
        else
            warn "拉取失败，第$attempt次重试（10秒后）..."
            sleep 10 && ((attempt++))
        fi
    done
fi

# 15. 生成节点配置文件
echo "[13/20] 生成节点配置文件..." | tee -a "$log_file"
mkdir -p deploy || error "无法创建deploy目录"
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
info "✅ 节点配置文件生成完成"

# 16. 启动容器服务（无限重试）
echo "[14/20] 启动节点容器..." | tee -a "$log_file"
cd deploy || error "无法进入deploy目录"
# 调整docker-compose依赖
if grep -q 'depends_on: \[ redis, infernet-anvil \]' docker-compose.yaml; then
    sed -i 's/depends_on: \[ redis, infernet-anvil \]/depends_on: [ redis ]/g' docker-compose.yaml
    cp docker-compose.yaml docker-compose.yaml.bak
    info "✅ docker-compose依赖已调整"
fi

# 启动容器（无限重试）
attempt=1
while true; do
    info "启动容器（第$attempt次）..."
    if sudo docker compose up -d; then
        sleep 5 # 等待服务初始化
        info "✅ 容器启动成功"
        break
    else
        warn "启动失败，第$attempt次重试（10秒后）..."
        sleep 10 && ((attempt++))
    fi
done

# 17. 安装Forge库（forge-std + infernet-sdk）
echo "[15/20] 安装Forge依赖库..." | tee -a "$log_file"
cd "$HOME/infernet-container-starter/projects/hello-world/contracts" || error "无法进入合约目录"
# 清理旧库
rm -rf lib/forge-std lib/infernet-sdk 2>/dev/null || warn "清理旧库失败，继续安装"

# 安装forge-std（无限重试）
attempt=1
while true; do
    if forge install foundry-rs/forge-std; then
        info "✅ forge-std安装成功"
        break
    else
        warn "forge-std安装失败，第$attempt次重试（10秒后）..."
        sleep 10 && ((attempt++))
    fi
done

# 安装infernet-sdk（无限重试）
attempt=1
while true; do
    if forge install ritual-net/infernet-sdk; then
        info "✅ infernet-sdk安装成功"
        break
    else
        warn "infernet-sdk安装失败，第$attempt次重试（10秒后）..."
        sleep 10 && ((attempt++))
    fi
done

# 18. 写入合约部署脚本（Deploy.s.sol）
echo "[16/20] 创建合约部署脚本..." | tee -a "$log_file"
mkdir -p script || error "无法创建script目录"
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
info "✅ Deploy.s.sol创建完成"

# 19. 写入Makefile
echo "[17/20] 创建Makefile..." | tee -a "$log_file"
cat <<'EOF' > Makefile
.PHONY: deploy
sender := $PRIVATE_KEY
RPC_URL := $RPC_URL
deploy:
	@PRIVATE_KEY=$(sender) forge script script/Deploy.s.sol:Deploy --broadcast --rpc-url $(RPC_URL)
EOF
info "✅ Makefile创建完成"

# 20. 部署合约（含RPC检查+调用）
echo "[18/20] 部署合约..." | tee -a "$log_file"
# 再次检查RPC连通性
attempt=1
while true; do
    if curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_chainId","id":1}' "$RPC_URL" | jq -e '.result' > /dev/null; then
        info "✅ RPC连通性正常"
        break
    else
        warn "RPC连接失败，第$attempt次重试（10秒后）..."
        sleep 10 && ((attempt++))
    fi
done
warn "⚠️  请确保私钥有足够余额支付Gas费用"

# 部署合约（无限重试，临时日志保存）
deploy_log=$(mktemp)
attempt=1
while true; do
    info "部署合约（第$attempt次）..."
    if PRIVATE_KEY="$PRIVATE_KEY" forge script script/Deploy.s.sol:Deploy --broadcast --rpc-url "$RPC_URL" > "$deploy_log" 2>&1; then
        info "✅ 合约部署成功！输出："
        cat "$deploy_log"
        break
    else
        warn "部署失败，详情：\n$(cat "$deploy_log")\n第$attempt次重试（10秒后）..."
        sleep 10 && ((attempt++))
    fi
done

# 提取合约地址并创建调用脚本
contract_address=$(grep -i "Deployed SaysGM" "$deploy_log" | awk '{print $NF}' | head -n 1)
if [ -n "$contract_address" ] && [[ "$contract_address" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    info "✅ 部署的SaysGM合约地址：$contract_address（请保存）"
    call_contract_file="script/CallContract.s.sol"

    # 创建/更新CallContract.s.sol
    if [ ! -f "$call_contract_file" ]; then
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
        chmod 644 "$call_contract_file"
        info "✅ CallContract.s.sol创建完成"
    else
        # 备份并更新现有文件
        cp "$call_contract_file" "${call_contract_file}.bak.$(date +%Y%m%d_%H%M%S)"
        sed -i "s|SaysGM(0x[0-9a-fA-F]\{40\})|SaysGM($contract_address)|g" "$call_contract_file"
        info "✅ CallContract.s.sol已更新合约地址"
    fi

    # 调用合约（无限重试）
    info "调用合约sayGM函数..."
    call_log=$(mktemp)
    attempt=1
    while true; do
        if PRIVATE_KEY="$PRIVATE_KEY" forge script "$call_contract_file" --broadcast --rpc-url "$RPC_URL" > "$call_log" 2>&1; then
            info "✅ 合约调用成功！输出："
            cat "$call_log"
            break
        else
            warn "调用失败，详情：\n$(cat "$call_log")\n第$attempt次重试（10秒后）..."
            sleep 10 && ((attempt++))
        fi
    done
    rm -f "$call_log"
else
    warn "⚠️  未提取到有效合约地址，请查看部署日志：$deploy_log"
fi
rm -f "$deploy_log"

# 21. 启动missing trie node自动跳过守护进程
echo "[19/20] 启动错误自动修复守护进程..." | tee -a "$log_file"
monitor_and_skip_trie_error() {
    local LOG_FILE="$HOME/infernet-deployment.log"
    local CONFIG_FILE="$HOME/infernet-container-starter/deploy/config.json"
    local COMPOSE_DIR="$HOME/infernet-container-starter/deploy"
    local LAST_BATCH_FILE="/tmp/ritual_last_batch.txt"

    info "守护进程启动：自动跳过missing trie node错误..."
    while true; do
        local line=$(grep "missing trie node" "$LOG_FILE" | tail -1)
        if [[ -n "$line" ]]; then
            local batch=$(echo "$line" | grep -oE "batch=\\([0-9]+, [0-9]+\\)")
            if [[ $batch =~ ([0-9]+),\ ([0-9]+) ]]; then
                local new_start=$(( ${BASH_REMATCH[2]} + 1 ))
                # 避免重复处理同一批次
                if [[ ! -f "$LAST_BATCH_FILE" || ! grep -q "$batch" "$LAST_BATCH_FILE" ]]; then
                    echo "$batch" > "$LAST_BATCH_FILE"
                    warn "检测到trie错误，跳过至区块$new_start并重启节点..."
                    jq ".chain.snapshot_sync.starting_sub_id = $new_start" "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
                    cd "$COMPOSE_DIR" && sudo docker compose restart node
                    sleep 60
                fi
            fi
        fi
        sleep 30
    done
}
# 后台启动守护进程
monitor_and_skip_trie_error &

# 22. 部署完成提示
echo "[20/20] ✅ 全部部署完成！" | tee -a "$log_file"
info "📌 部署日志：$log_file"
info "📌 节点状态：sudo docker compose -f $HOME/infernet-container-starter/deploy/docker-compose.yaml ps"
info "📌 节点日志：sudo docker logs -f infernet-node"
info "📌 再次调用合约：PRIVATE_KEY=$PRIVATE_KEY forge script script/CallContract.s.sol --broadcast --rpc-url $RPC_URL"
info "⚠️  守护进程后台运行，按Ctrl+C可停止脚本（容器继续运行）"

exit 0
