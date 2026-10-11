FROM python:3.11-slim

# 装 git（审计时跑 git log 等）
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制框架代码
COPY . /app

# 依赖：纯 stdlib，不需要 pip install
# 但装一下 pyyaml（如果用的话）
RUN pip install --no-cache-dir pyyaml

# 工作目录：审计目标挂载点
VOLUME ["/targets", "/audit-out"]

# 默认入口：bash（可以 docker exec 进去跑命令）
CMD ["bash"]
