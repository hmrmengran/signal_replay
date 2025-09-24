# Dockerfile
FROM python:3.11-slim

# 可选调试：tcpdump/iproute2 便于容器内排查网卡与流量
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump iproute2 procps \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 先装依赖，提升缓存命中率
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 拷贝源码
COPY . .

ENV PYTHONUNBUFFERED=1

# 你的程序默认入口，实际参数在 docker run / compose 里传
ENTRYPOINT ["python", "signal_replay.py"]

