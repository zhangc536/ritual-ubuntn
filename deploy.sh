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
import { Account, PrivateKey, Aptos, Ed25519PrivateKey } from "@aptos-labs/ts-sdk";
import fs from "fs";

const rawKey = "$PRIVATE_KEY_CLEAN";
const formatted = PrivateKey.formatPrivateKey(rawKey, "ed25519");
const privateKey = new Ed25519PrivateKey(formatted);
const account = Account.fromPrivateKey({ privateKey });

const client = new ShelbyNodeClient({
  fullnode: "https://api.shelby.xyz",
  indexer: {
    endpoint: "https://indexer.shelby.xyz",
  },
});

const aptos = new Aptos({
  fullnode: "https://fullnode.shelby.xyz",
});

async function checkBalance(address) {
  try {
    const balance = await aptos.getAccountAPTAmount({
      accountAddress: address,
    });
    console.log("💰 当前余额:", balance, "APT");
    return Number(balance);
  } catch (err) {
    console.error("❌ 查询余额失败:", err);
    return 0;
  }
}

async function checkShelbyUSD(address) {
  try {
    const resources = await aptos.getAccountResources({
      accountAddress: address,
    });

    let found = false;

    for (const r of resources) {
      if (
        r.type.toLowerCase().includes("shelby") &&
        r.type.toLowerCase().includes("blob")
      ) {
        console.log("📦 发现资源:", r.type);
        console.log("📊 内容:", JSON.stringify(r.data, null, 2));
        found = true;
      }
    }

    if (!found) {
      console.log("⚠️ 未找到 ShelbyUSD 相关资源（可能没有余额）");
    }

  } catch (err) {
    console.error("❌ 查询 ShelbyUSD 失败:", err);
  }
}

async function run() {
  const file = "./data/test.txt";

  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, "hello " + Date.now());
  }

  const address = account.accountAddress.toString();

  await checkShelbyUSD(address);

  const balance = await checkBalance(address);

  if (balance < 1) {
    console.log("⚠️ 余额不足，跳过本次上传");
    return;
  }

  const data = new Uint8Array(fs.readFileSync(file));
  const blobName = "auto-" + Date.now() + ".txt";

  console.log("📤 上传:", blobName);

  await client.upload({
    signer: account,
    blobData: data,
    blobName,
    expirationMicros: BigInt(Date.now()) * 1000n + 3600_000_000n,
  });

  console.log("✅ 上传成功");

  const res = await client.download({
    signer: account,
    blobName,
  });

  if (!fs.existsSync("./downloads")) {
    fs.mkdirSync("./downloads");
  }

  fs.writeFileSync("./downloads/" + blobName, res);

  console.log("📥 下载完成:", blobName);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
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
    echo "⏳ 等待 12 小时..."
    sleep 43200
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
