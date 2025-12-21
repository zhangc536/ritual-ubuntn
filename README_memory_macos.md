# macOS 内存读取 + 自动放置（PoC）说明

本项目提供两个 macOS 脚本：

- `memory_probe_macos.py`：只读探测，枚举内存并启发式搜索 `[x,y,z,type]` 结构，输出与蓝图差异报告。
- `memory_place_macos.py`：按配置读取状态区域，与蓝图比对后使用 Mach 内存写入执行自动放置；支持在放置前自动移动与朝向（需填写移动相关地址）。支持 `--auto-state` 自动扫描世界状态（无需预填 `state_region`）。
  - 现已支持 `--auto-all` 一键自动：自动状态扫描、蓝图差异放置；若未配置 `placement`，将直接写入状态区域；同时尝试自动发现 `movement`（风险较高）。
 - `memory_discover_macos.py`：地址发现工具。按你在游戏里设置的“唯一坐标”或“唯一整数值”在进程内扫描候选地址，并提供交叉验证与可选写入测试。

## 强烈的风险与合规提示

- 仅用于离线、自有环境研究及学习目的；请严格遵守目标软件/游戏的 EULA 与法律法规。
- 需要较高权限（通常 `sudo`），并可能受 SIP/TCC/签名/entitlements 限制。
- 实际地址、偏移、触发机制必须由你使用调试器/逆向工具确认；脚本不包含任何绕过或注入手段。

## 蓝图格式

- 支持两种：
  - 对象式：`[{"pos": [x,y,z], "type": block_type}, ...]`
  - 兼容旧格式：`[[...], [...], [x,y,z], [type_list,...], action]`

## 配置文件

- 复制 `memory_layout.template.json` 为 `memory_layout.json` 并填写：

```json
{
  "state_region": {
    "address": "0x...",        // 方块状态数组基址
    "size": 1048576,             // 读取字节大小（按实际）
    "stride": 16,                 // 单个元素步长
    "fields": {"x":0,"y":4,"z":8,"type":12},
    "bounds": {"x":[-4096,4096],"y":[-4096,4096],"z":[-4096,4096],"type":[0,4096]}
  },
  "placement": {
    "buffer_address": "0x...",   // 写入的放置缓冲基址
    "fields": {"x":0,"y":4,"z":8,"type":12},
    "trigger": {"address": "0x...", "value": 1, "size": 4}, // 触发写入/事件的地址与值
    "override_protection": false  // 若目标不可写，尝试设置可写（高风险）
  },
  "movement": {
    "player_pos": {"address": "0x...", "fields": {"x":0,"y":4,"z":8}, "dtype": "float"},
    "move_to": {"address": "0x...", "fields": {"x":0,"y":4,"z":8}, "dtype": "float", "trigger": {"address": "0x...", "value": 1, "size": 4}, "override_protection": false},
    "look_at": {"address": "0x...", "mode": "angles", "fields": {"yaw":0, "pitch":4}, "dtype": "float", "trigger": {"address": "0x...", "value": 1, "size": 4}, "override_protection": false},
    "arrival_radius": 1.5,
    "arrival_timeout_ms": 5000,
    "approach_offset": [0.5, 0.0, 0.5] // 站位到目标方块前（默认向方块中心靠近）
  }
}
```

## 使用方法

1) 只读探测（差异报告）：

```
sudo python3 memory_probe_macos.py --name GameBinaryName --blueprint blueprint.json --limit-mb 256 --output probe_result.json
```

2) 自动放置（自动移动 + 放置）：

```
sudo python3 memory_place_macos.py --name GameBinaryName --config memory_layout.json --limit 10000
```

- 蓝图路径固定为仓库根目录的 `blueprint.json`。
- 干跑（不写入）：`--dry-run`
- 通过 PID 运行：`--pid 1234`
- 十六进制地址在配置中用 `0x...` 书写即可。

可选：自动扫描世界状态（跳过 `state_region` 配置）
```
sudo python3 memory_place_macos.py --name GameBinaryName --auto-state --auto-state-limit-mb 128 --limit 100
```
说明：`--auto-state` 会遍历进程的可读内存，按启发式识别 `[x,y,z,type]` 记录并构建当前世界状态，用于与蓝图做差异比对。

一键全自动：
```
sudo python3 memory_place_macos.py --name GameBinaryName --auto-all --auto-state-limit-mb 128 --limit 100
```
- 自动扫描世界状态（无需配置 `state_region`）。
- 若缺少 `placement`，直接向状态区域的记录写入 `type`（基于扫描得到的地址映射）。
- 尝试自动发现 `movement`（通过写测试推测玩家坐标地址，具风险，可能导致瞬移或引擎校正）。

地址发现（更安全的预检测流程）：
- 步骤 1：在游戏里设置一个唯一坐标（例如 `x=4321.1234,y=64,z=9876.4321`）。
- 步骤 2：运行坐标搜索，得到候选地址列表：
```
sudo python3 memory_discover_macos.py --name GameBinaryName --mode search-xyz --x 4321.1234 --y 64 --z 9876.4321 --limit-mb 128 --max-results 2048 --output run1.json
```
- 步骤 3：改变到另一个唯一坐标，再次搜索并取交集缩小候选：
```
sudo python3 memory_discover_macos.py --name GameBinaryName --mode search-xyz --x 12345.5 --y 65 --z 54321.25 --output run2.json
sudo python3 memory_discover_macos.py --mode intersect --inputs run1.json run2.json --output narrow.json
```
- 步骤 4：在新坐标下验证候选是否匹配（只读）：
```
sudo python3 memory_discover_macos.py --name GameBinaryName --mode verify-xyz --x 12345.5 --y 65 --z 54321.25 --inputs narrow.json
```
- 步骤 5（可选，风险高）：对极少量候选做写测试以确认可控：
```
sudo python3 memory_discover_macos.py --name GameBinaryName --mode write-xyz --x 100.0 --y 64.0 --z 100.0 --inputs narrow.json --require-writable --dry-run
# 移除 --dry-run 后将实际写入（慎用）
```
- 验证成功后，可将地址填入 `memory_layout.json` 的 `movement.player_pos`/`movement.move_to`，或直接使用 `memory_place_macos.py --auto-all`。

自动移动说明：
- 若 `movement.move_to` 与 `movement.player_pos` 已正确填写，脚本会在每个方块放置前：
  - 写入目标站位点（`approach_offset` 相对方块坐标，默认靠近方块中心）。
  - 等待到达（`arrival_radius` 与 `arrival_timeout_ms` 可调）。
  - 校准视角（`look_at`：角度模式或“看向坐标”模式）。
  - 然后执行内存写入的实际放置。
- 如未填写 `movement`，将直接尝试放置（无自动移动）。

## 建议的确认步骤

- 先使用 `memory_probe_macos.py` 验证状态区域解析正确（差异数量合理）。
- 小范围放置（`--limit` 设置很小）并观察是否生效；失败时检查地址、偏移、触发逻辑是否准确。
- 若 `mach_vm_write` 报保护错误，可谨慎启用 `override_protection`，但强烈不推荐在生产系统上更改保护。
- 自动移动失败（到达超时或读不到坐标）：将继续尝试放置，你可调大 `arrival_timeout_ms` 或检查地址与字段。
 - 自动世界状态：`--auto-state` 为通用启发式，适用于多数 16 字节布局；若你的引擎使用不同结构或坐标范围，请调整过滤范围与脚本逻辑。
- `--auto-all` 的移动地址发现基于写入测试：仅在你能接受风险时使用；如不希望脚本写入未知坐标，可仅使用 `--auto-state` + 直接写入状态区域完成放置。
 - 地址发现流程更安全：先做坐标探针（唯一值），多次搜索并交集缩小候选，再只读验证，最后在可控环境下少量写测试。

## 常见问题

- `task_for_pid` 返回非 0：需使用 `sudo`，并确保目标不是受保护进程；可能需要关闭或调整相关限制（不建议）。
- 读到的数据噪声大：调整 `bounds`、`stride` 或改为更精确的结构体解析；必要时分区读取。
- 写入无效：游戏可能需要队列/事件机制；尝试写触发字段或函数调用（需额外研究）。

## 后续工作

- 若你提供具体的地址、偏移或事件触发机制，我可以将脚本适配为更精准的解析和放置逻辑，并加入失败重试与速率控制。
