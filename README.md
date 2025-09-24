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
├── Dockerfile
├── phases.ndjson
├── README.md
├── recordings-000001.ndjson
├── requirements.txt
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
  --base-url http://127.0.0.1:8000 \
  --file phases.ndjson \
  --lidar-mode fake \
  --fake-subnet 172.30.0.0/24 \
  --lidar-port 8011 \
  --log-level DEBUG 
```
#### --fake-subnet 是 必填 的；程序会调用 discovery_fake_lidar_interface(<subnet>) 自动选择网卡。

或者真实 LiDAR：
```bash
sudo python3 signal_replay.py \
  --base-url http://127.0.0.1:8000 \
  --file phases.ndjson \
  --lidar-mode real \
  --lidar-port 8011 \
  --log-level INFO
```

---

## 命令行参数说明（`signal_replay.py`）
```bash
参数	              是否必填	说明
--base-url	          是	     SDLC 服务地址，如 http://127.0.0.1:8000
--file	              是	     待回放的 NDJSON 文件路径
--speed	              否	回放倍率（占位，实际以 LiDAR 时间触发）
--token	              否	Bearer Token
--dry-run	            否	只打印将发送的数据，不实际 POST
--log-level	          否	DEBUG/INFO/WARNING/ERROR
--retries / --backoff	否	失败重试次数与首个回退秒数
--lidar-mode	        是	real 或 fake（自动发现对应网卡）
--fake-subnet	在 fake 模式下必填	例如 172.30.0.0/24，用于“假 LiDAR”网卡发现
--lidar-port	        否	LiDAR UDP 端口，默认值 8011
--l2-bpf	            否	追加 BPF 过滤表达式（默认 udp and port <lidar-port>）
--l2-iface	          否	当前版本预留/忽略：实际以自动发现的网卡为准
--prologue-empty	    否	启用前置帧
--prologue-offset-ms	否	前置帧相对首帧时间的偏移（默认 -1）
--prologue-phases	    否	前置帧相位模板或 none 发送空帧

> 代码参考：`parse_args()` 与 `L2PcapTimeSource` 的实现。
```
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

## Docker 运行（可选）

# 构建
docker build -t signal-replay:latest .

# 运行（需要抓包权限）
```bash
docker run --rm -it \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -v "$(pwd)/phases.ndjson:/app/phases.ndjson:ro" \
  signal-replay:latest \
  --base-url http://172.16.210.49:8000 \
  --file /app/phases.ndjson \
  --lidar-port 8011 \
  --lidar-mode fake

--net=host 与 --cap-add NET_* 在容器里抓包通常必需；根据你的 Dockerfile/基础镜像适当调整。
```

## 权限与常见问题（Troubleshooting）

1. **抓包无数据 / 报错权限不足** 
   - 用 `sudo` 运行，或给 Python 解释器设置 `cap_net_raw,cap_net_admin`。 
   - 确认机器上安装了 `libpcap`（参考前文系统依赖）。

2. **sudo 下报 NameError: name 'threading' is not defined** 
   - 当你用 sudo 跑时，root 的 Python 环境里 没有安装 scapy，这一行 from scapy.all ... 触发 ImportError，
   - 于是整个 try 被跳过，threading 也就没有被导入。随后在 ReplayController.__init__ 里用到了 threading.Lock()，
   - 于是直接 NameError: name 'threading' is not defined。。

3. **无法发现“假 LiDAR”** 
   - 记得传入 --fake-subnet（例如 172.30.0.0/24）；
   - 确认容器/桥接网卡确实在该子网，并且端口与 --lidar-port 一致；
   - 提高日志级别 --log-level DEBUG 查看发现日志。

4. **NDJSON 被判为无效** 
   - 查看日志（`--log-level DEBUG`）； 
   - 校验 `ts_ms` 类型为 **整型** 毫秒；`veh/ped` 值是否在允许集合内。

---

## 许可证

（可选）选择合适的开源协议，如 MIT；或在此处添加内部版权说明。
