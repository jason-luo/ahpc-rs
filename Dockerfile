# ahpc —— 发布版为单文件静态二进制（musl static），运行时零依赖。
#
# 镜像里只有两个文件，全部来自构建上下文：
#   /ahpc          静态链接的 ahpc 客户端
#   /client.json   内置配置（服务端地址、RSA 公钥、cipher、listen_port 等）
#
# 用法（scripts/build-image.sh 会自动准备构建上下文）：
#   ./scripts/build-image.sh            # 构建 ahpc:1.0（linux/arm64）
#   ./scripts/build-image.sh --save     # 额外导出可上传的镜像 tar.gz
#
# 手动构建示例（上下文必须同时包含 ahpc 和 client.json）：
#   mkdir -p /tmp/ctx
#   cp target/aarch64-unknown-linux-musl/release/ahpc /tmp/ctx/
#   cp client.json /tmp/ctx/
#   podman build --platform linux/arm64 -f Dockerfile -t ahpc:1.0 /tmp/ctx
FROM scratch

COPY ahpc /ahpc
COPY client.json /client.json

# ahpc 只接受一个位置参数：配置文件路径（见 src/main.rs）。
# 默认使用镜像内置配置；运行时可以覆盖：
#   podman run --rm -p 127.0.0.1:8089:8089 ahpc:1.0 /other-client.json
ENTRYPOINT ["/ahpc"]
CMD ["/client.json"]

# 实际监听端口由 client.json 的 listen_port 决定（默认 8089），此处仅作声明。
EXPOSE 8089

# ahpc 只注册了 SIGINT 处理（tokio::signal::ctrl_c）。
# scratch 镜像没有 init，进程就是 PID 1：未安装处理函数的 SIGTERM 会被内核忽略，
# 默认情况下 podman stop 会干等 10 秒再 SIGKILL。
# 把镜像的 stop signal 映射到进程真正处理的 SIGINT，实现秒级干净退出。
STOPSIGNAL SIGINT
