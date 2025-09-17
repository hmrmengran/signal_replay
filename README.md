# Signal Replay & LiDAR Discovery

一个用于**发现 LiDAR 网卡**并**回放相位（phase）NDJSON**到 SDLC 服务的小工具集。包含：

- `discover_live_lidar.py`：在真实网络里通过广播搜索 Innovusion LiDAR（16800 端口）【针对实机】
- `discover_fake_lidar.py`：在指定子网（默认 `172.30.0.0/24`）与端口（默认 `8011`）监听，发现“假 LiDAR”（容器/仿真）【针对测试】
- `signal_replay.py`：从 `*.ndjson` 文件读取相位快照，按 LiDAR UDP 报文时间戳进行对齐并 POST 到 SDLC 接口

> 目前代码以 Linux/WSL 环境为主，抓包使用 `scapy` 的 `AsyncSniffer`，需要 root 权限或相应 `cap` 能力。

---

## 目录结构

```
├── discover_fake_lidar.py
├── discover_live_lidar.py
├── phases.ndjson
├── README.md
└── signal_replay.py
```

---

## 运行前准备

### 1) Python 依赖

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) 系统依赖（建议）

- Linux 下抓包推荐安装：
  ```bash
  sudo apt-get update
  sudo apt-get install -y tcpdump libpcap-dev
  ```
- 运行抓包/绑定网卡需要 root 权限。你可以直接用 `sudo` 运行，或给 Python 解释器授予能力（择一）：
  ```bash
  # 方式A：sudo 运行
  sudo python3 signal_replay.py ...

  # 方式B：授予cap（更细粒度；需根据你的python路径调整）
  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
  ```

---

## 快速上手

### A. 发现真实 LiDAR（广播，16800）
```bash
sudo python3 discover_live_lidar.py
```
如果发现成功，会打印设备信息并返回所在网卡名。

### B. 发现“假 LiDAR”（仿真/容器，UDP 8011）
```bash
sudo python3 discover_fake_lidar.py
```
默认在 `172.30.0.0/24` 子网中监听 UDP:8011 数据。如需修改子网或端口，可在脚本内部调整常量或扩展参数。

### C. NDJSON 相位回放（按 LiDAR 报文时间戳对齐）

`signal_replay.py` 会：
1. 自动发现 LiDAR 网卡（`--lidar-mode` 控制真实/仿真）；
2. 在该网卡上用 BPF 过滤（默认 `udp and port <lidar-port>`）抓取 LiDAR UDP 报文；
3. 解析 InnoDataPacketV1 的 `ts_start_us`；
4. 当 LiDAR 时间与 NDJSON 中的 `ts_ms`（支持容忍度）匹配时，将该条快照 `POST` 到 SDLC。

示例：
```bash
# 假 LiDAR 模式（默认端口 8011），回放 phases.ndjson 到本地 SDLC
sudo python3 signal_replay.py \
  --base-url http://127.0.0.1:8080 \
  --file phases.ndjson \
  --lidar-mode fake \
  --lidar-port 8011 \
  --log-level DEBUG 
```

或者真实 LiDAR：
```bash
sudo python3 signal_replay.py \
  --base-url http://127.0.0.1:8080 \
  --file phases.ndjson \
  --lidar-mode real \
  --lidar-port 8011 \
  --log-level INFO
```

---

## 命令行参数说明（`signal_replay.py`）

| 参数 | 说明 |
|---|---|
| `--base-url` | **必填**。SDLC 服务地址，如 `http://127.0.0.1:8080` |
| `--file` | **必填**。待回放的 NDJSON 记录文件路径 |
| `--speed` | 回放速度倍率（当前实现以 LiDAR 时间为触发，`speed` 预留） |
| `--token` | 可选的 Bearer Token |
| `--dry-run` | 只打印将要发送的数据，不实际 POST |
| `--log-level` | 日志级别：`DEBUG/INFO/WARNING/ERROR` |
| `--retries` / `--backoff` | 发送失败重试次数与首个回退秒数 |
| `--lidar-mode` |**必填** `real`（自动发现真实网卡）或 `fake`（自动发现测试子网网卡） |
| `--lidar-port` |**必填** LiDAR UDP 端口，真实常见为 `2368`，仿真例子为 `8011` |
| `--l2-bpf` | 自定义 BPF 过滤表达式（默认 `udp and port <lidar-port>`） |

> 代码参考：`parse_args()` 与 `L2PcapTimeSource` 的实现。

---

## NDJSON 格式

文件为一行一条 JSON，支持结构：
```json
{"type":"phase","ts_ms":1736940005123,"data":[{"phase":1,"state":{"veh":"G","ped":"NA"}}]}
```

字段约束：
- `type` 目前仅支持 `"phase"`
- `veh` 取值：`G/Y/R`
- `ped` 取值：`NA/WALK/DONT_WALK`

---

## 权限与常见问题（Troubleshooting）

1. **抓包无数据 / 报错权限不足**  
   - 用 `sudo` 运行，或给 Python 解释器设置 `cap_net_raw,cap_net_admin`。  
   - 确认机器上安装了 `libpcap`（参考前文系统依赖）。

2. **无法发现“假 LiDAR”**  
   - 默认只在 `172.30.0.0/24` 子网 + `8011` 端口监听，确保数据源与端口一致；  
   - 容器/桥接网卡（`veth*` / `br-*`）是否在该子网；  
   - 可调整 `discover_fake_lidar.py` 中的子网和端口。

3. **NDJSON 被判为无效**  
   - 查看日志（`--log-level DEBUG`）；  
   - 校验 `ts_ms` 类型为 **整型** 毫秒；`veh/ped` 值是否在允许集合内。

---

## 开发建议

- 使用 `pytest` 编写单测（对解析和匹配逻辑进行覆盖）；  
- 使用 `black`/`flake8` 保持风格统一；  
- 添加 `CHANGELOG.md` 和 `LICENSE`；  
- 如需跨平台支持，建议在 README 追加 Windows/macOS 注意事项。

---

## 许可证

（可选）选择合适的开源协议，如 MIT；或在此处添加内部版权说明。
