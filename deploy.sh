#!/bin/bash

echo ""
echo "=============================="
echo "🚀 Shelby 全自动初始化系统"
echo "=============================="
echo ""

PROJECT="shelby-auto"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 1/15: 创建项目目录"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
mkdir -p $PROJECT
cd $PROJECT
echo "✅ 目录创建完成: $PROJECT"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 2/15: 检查 Node.js 环境"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if ! command -v node &> /dev/null
then
    echo "❌ 请先安装 Node.js"
    exit 1
fi
echo "✅ Node 版本: $(node -v)"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 3/15: 初始化 npm 项目"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
npm init -y > /dev/null 2>&1
echo "✅ npm 初始化完成"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 4/15: 设置 ES Module"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
node -e '
const fs = require("fs");
let pkg = JSON.parse(fs.readFileSync("package.json"));
pkg.type = "module";
fs.writeFileSync("package.json", JSON.stringify(pkg, null, 2));
'
echo "✅ ES Module 设置完成"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 5/15: 安装依赖包"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⏳ 正在安装 @shelby-protocol/sdk @aptos-labs/ts-sdk ..."
npm install @shelby-protocol/sdk @aptos-labs/ts-sdk > /dev/null 2>&1
echo "✅ 依赖安装完成"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 6/15: 创建数据目录"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
mkdir -p data downloads
echo "✅ 目录创建完成: data/, downloads/"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 7/15: 生成钱包"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat > gen_wallet.js <<EOF
import { Account } from "@aptos-labs/ts-sdk";
const acc = Account.generate();
console.log("ADDRESS=" + acc.accountAddress.toString());
console.log("PRIVATE_KEY=" + acc.privateKey.toString());
EOF

INFO=$(node gen_wallet.js)

ADDRESS=$(echo "$INFO" | grep ADDRESS | cut -d '=' -f2)
PRIVATE_KEY=$(echo "$INFO" | grep PRIVATE_KEY | cut -d '=' -f2)

PRIVATE_KEY_CLEAN=$(echo "$PRIVATE_KEY" | sed 's/^ed25519-priv-//')

echo "✅ 钱包生成完成"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 8/15: 保存钱包信息"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
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

echo "✅ 钱包已保存到 wallet.txt"
echo "📍 钱包地址: $ADDRESS"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 9/15: 创建主程序 main.js"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat > main.js <<EOF
import { ShelbyNodeClient } from "@shelby-protocol/sdk/node";
import { Account, Network, Ed25519PrivateKey } from "@aptos-labs/ts-sdk";
import fs from "fs";

const privateKey = new Ed25519PrivateKey("$PRIVATE_KEY_CLEAN");
const account = Account.fromPrivateKey({ privateKey });

const client = new ShelbyNodeClient({
  network: Network.TESTNET,
});

async function run() {
  const file = "./data/test.txt";

  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, "hello " + Date.now());
  }

  const data = new Uint8Array(fs.readFileSync(file));
  const blobName = "auto-" + Date.now() + ".txt";

  console.log("📤 上传:", blobName);

  await client.upload({
    signer: account,
    blobData: data,
    blobName: String(blobName),
    expirationSecs: BigInt(3600),
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

echo "✅ main.js 创建完成"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 10/15: 创建 run.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat > run.sh <<EOF
#!/bin/bash

cd "$(dirname "\$0")"

echo "📁 当前目录: \$(pwd)"

if [ ! -f "./main.js" ]; then
    echo "❌ main.js 不存在！请检查项目结构"
    exit 1
fi

while true
do
    echo "🚀 执行任务 \$(date)"
    node ./main.js
    echo "⏳ 等待 30 秒..."
    sleep 30
done
EOF

chmod +x run.sh
echo "✅ run.sh 创建完成"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 11/15: 创建 start.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
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
echo "✅ start.sh 创建完成"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 12/15: 创建 stop.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
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
echo "✅ stop.sh 创建完成"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 13/15: 创建 status.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
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
echo "✅ status.sh 创建完成"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 14/15: 创建 logs.sh"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cat > logs.sh <<EOF
#!/bin/bash
tail -f shelby.log
EOF

chmod +x logs.sh
echo "✅ logs.sh 创建完成"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📌 步骤 15/15: 创建测试文件"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "hello shelby $(date)" > data/test.txt
echo "✅ 测试文件创建完成"
echo ""

echo "=============================="
echo "🎉 初始化完成！"
echo "=============================="
echo ""
echo "📄 钱包信息: wallet.txt"
echo "⚠️ 记得去 Faucet 领取测试币"
echo ""
echo "👉 启动命令:"
echo "   cd $PROJECT"
echo "   ./start.sh"
echo ""
echo "👉 查看日志:"
echo "   ./logs.sh"
echo ""
echo "👉 查看状态:"
echo "   ./status.sh"
echo ""
