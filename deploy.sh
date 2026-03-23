#!/bin/bash

echo "=============================="
echo "🚀 Shelby 全自动初始化系统"
echo "=============================="

PROJECT="shelby-auto"

# ===== 1. 创建项目目录 =====
mkdir -p $PROJECT
cd $PROJECT

# ===== 2. 检查 Node =====
if ! command -v node &> /dev/null
then
    echo "❌ 请先安装 Node.js"
    exit 1
fi

echo "✅ Node: $(node -v)"

# ===== 3. 初始化 npm =====
npm init -y > /dev/null 2>&1

# ===== 4. 设置 ES Module =====
node -e '
const fs = require("fs");
let pkg = JSON.parse(fs.readFileSync("package.json"));
pkg.type = "module";
fs.writeFileSync("package.json", JSON.stringify(pkg, null, 2));
'

# ===== 5. 安装依赖 =====
npm install @shelby-protocol/sdk @aptos-labs/ts-sdk > /dev/null 2>&1

# ===== 6. 创建目录 =====
mkdir -p data downloads

# ===== 7. 生成钱包 =====
cat > gen_wallet.js <<EOF
import { Account } from "@aptos-labs/ts-sdk";
const acc = Account.generate();
console.log("ADDRESS=" + acc.accountAddress.toString());
console.log("PRIVATE_KEY=" + acc.privateKey.toString());
EOF

INFO=$(node gen_wallet.js)

ADDRESS=$(echo "$INFO" | grep ADDRESS | cut -d '=' -f2)
PRIVATE_KEY=$(echo "$INFO" | grep PRIVATE_KEY | cut -d '=' -f2)

# ===== 8. 保存钱包 =====
cat > wallet.txt <<EOF
==============================
⚠️ 保存好你的钱包
==============================

地址:
$ADDRESS

私钥:
$PRIVATE_KEY

⚠️ 不要泄露
==============================
EOF

echo "✅ 钱包生成: $ADDRESS"

# ===== 9. 主程序 =====
cat > main.js <<EOF
import { ShelbyNodeClient } from "@shelby-protocol/sdk/node";
import { Account, Network } from "@aptos-labs/ts-sdk";
import fs from "fs";

const account = Account.fromPrivateKey("$PRIVATE_KEY");

const client = new ShelbyNodeClient({
  network: Network.TESTNET,
});

async function run() {
  const file = "./data/test.txt";

  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, "hello " + Date.now());
  }

  const data = fs.readFileSync(file);
  const blobName = "auto-" + Date.now() + ".txt";

  console.log("📤 上传:", blobName);

  await client.upload({
    signer: account,
    blobData: data,
    blobName,
    expirationSecs: 3600,
  });

  console.log("✅ 上传成功");

  const res = await client.download({
    account,
    blobName,
  });

  fs.writeFileSync("./downloads/" + blobName, res);

  console.log("📥 下载完成:", blobName);
}

run();
EOF

# ===== 10. run.sh =====
cat > run.sh <<EOF
#!/bin/bash
cd $(dirname "$0")

while true
do
    echo "🚀 执行任务 $(date)"
    node main.js
    echo "⏳ 等待 12 小时..."
    sleep 43200
done
EOF

chmod +x run.sh

# ===== 11. start.sh =====
cat > start.sh <<EOF
#!/bin/bash
cd \$(dirname "\$0")

if [ -f shelby.pid ]; then
    PID=\$(cat shelby.pid)
    if ps -p \$PID > /dev/null 2>&1; then
        echo "⚠️ 已运行 (PID: \$PID)"
        exit 1
    fi
fi

nohup ./run.sh > shelby.log 2>&1 &
echo \$! > shelby.pid

echo "✅ 启动成功 PID=\$(cat shelby.pid)"
EOF

chmod +x start.sh

# ===== 12. stop.sh =====
cat > stop.sh <<EOF
#!/bin/bash

if [ ! -f shelby.pid ]; then
    echo "❌ 未运行"
    exit 1
fi

PID=\$(cat shelby.pid)

if ps -p \$PID > /dev/null 2>&1; then
    kill \$PID
    rm shelby.pid
    echo "🛑 已停止"
else
    echo "⚠️ 进程不存在"
    rm shelby.pid
fi
EOF

chmod +x stop.sh

# ===== 13. status.sh =====
cat > status.sh <<EOF
#!/bin/bash

if [ ! -f shelby.pid ]; then
    echo "❌ 未运行"
    exit 1
fi

PID=\$(cat shelby.pid)

if ps -p \$PID > /dev/null 2>&1; then
    echo "✅ 运行中 PID=\$PID"
else
    echo "❌ 未运行"
fi
EOF

chmod +x status.sh

# ===== 14. logs.sh =====
cat > logs.sh <<EOF
#!/bin/bash
tail -f shelby.log
EOF

chmod +x logs.sh

# ===== 15. 测试文件 =====
echo "hello shelby $(date)" > data/test.txt

# ===== 完成 =====
echo ""
echo "=============================="
echo "🎉 初始化完成"
echo "=============================="
echo ""
echo "📄 钱包已保存 wallet.txt"
echo "⚠️ 记得去 Faucet 领测试币"
echo ""
echo "👉 使用："
echo "cd $PROJECT"
echo "./start.sh"
echo ""