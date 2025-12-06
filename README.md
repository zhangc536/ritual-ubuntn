# ritual-ubuntn

## 使用概览
- 在 Linux 服务器上运行：`bash hy2.sh`
- 默认端口 `443/udp`，自动生成 ECDSA P‑256 自签证书与 Clash 订阅。
- 订阅地址：`http://<服务器IP>:8080/clash_subscription.yaml`。

## 极限优化（默认开启）
- 关闭混淆：`DISABLE_OBFS=1`
- 禁用 GRO/GSO：`DISABLE_GRO_GSO=1`
- 队列控制：`ENABLE_TC_QDISC=2`（cake，自动回退 fq_codel）
- UDP notrack：`NOTRACK_UDP=1`
- conntrack 上限：`CONNTRACK_MAX=1048576`
- Clash 故障转移：`ENABLE_FALLBACK=1`，规则默认 `MATCH,故障转移`

## 进一步优化开关（按需）
- DSCP 标记：`ENABLE_DSCP=1`，`DSCP_OUT_CLASS=EF`（可设 `CS7`、`AF31` 或数值）
- cake 参数：`TC_CAKE_DIFFSERV=diffserv3`，`TC_CAKE_OPTS="nat"`
- fq_codel 参数：`TC_FQ_CODEL_OPTS="flows 1024"`
- 网卡环形缓冲：`SET_NIC_RING=1 RX_RING=4096 TX_RING=4096`
- Busy Poll/NAPI 预算：`ENABLE_BUSY_POLL=1 NET_BUSY_POLL=50 NET_BUSY_READ=50 NETDEV_BUDGET_USECS=80 NETDEV_BUDGET=300 DEV_WEIGHT=64`
- 网卡中断合并：`SET_NIC_COALESCE=1 RX_COALESCE_USECS=16 TX_COALESCE_USECS=16`

## 运行时网络调优（可配置）
- `NET_RMEM_MAX=33554432`、`NET_WMEM_MAX=33554432`
- `NET_RMEM_DEF=262144`、`NET_WMEM_DEF=262144`
- `NET_BACKLOG=250000`、`DEFAULT_QDISC=fq`
- `UDP_RMEM_MIN=16384`、`UDP_WMEM_MIN=16384`

## 示例
```bash
# 默认极限模式
bash hy2.sh

# 启用 DSCP 与环形缓冲
ENABLE_DSCP=1 DSCP_OUT_CLASS=EF SET_NIC_RING=1 RX_RING=4096 TX_RING=4096 bash hy2.sh

# 极限低延迟（Busy Poll + 中断合并 + cake diffserv）
ENABLE_BUSY_POLL=1 NET_BUSY_POLL=50 NET_BUSY_READ=50 SET_NIC_COALESCE=1 RX_COALESCE_USECS=16 TX_COALESCE_USECS=16 ENABLE_TC_QDISC=2 TC_CAKE_DIFFSERV=diffserv4 bash hy2.sh

# 更温和的模式
DISABLE_GRO_GSO=0 ENABLE_TC_QDISC=1 NOTRACK_UDP=0 ENABLE_FALLBACK=0 bash hy2.sh
```

## 验证
- 队列：`tc qdisc show dev <iface>`
- 网卡 offload：`ethtool -k <iface>`
- DSCP：`iptables -t mangle -S | grep DSCP` 或 `nft list ruleset | grep dscp`
- 订阅：导入 `http://<服务器IP>:8080/clash_subscription.yaml`
