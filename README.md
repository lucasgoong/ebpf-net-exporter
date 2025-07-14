# ebpf-net-exporter
使用eBPF技术达到监控指定进程的网络通信情况的Prometheus Exporter

## 编译和运行
### 1.编译eBPF程序
```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
      -I/usr/include/x86_64-linux-gnu \
      -c bpf/netstats.bpf.c -o bpf/netstats.bpf.o
```

### 2.编译go程序
```bash
go build -o ebpf-net-exporter cmd/main.go
```

### 3.运行（需要root权限）
```bash
sudo ./ebpf-net-exporter -config config/processes.conf -listen :9101
```

### 4.访问指标
```bash
curl http://localhost:9101/metrics
```

## 关键功能说明
  1.eBPF 程序：
  - 通过 tracepoint 捕获网络数据包
  - 使用哈希表统计流量和连接信息
  - 支持按进程过滤（基于 PID）

  2.Go 程序：
  - 加载 eBPF 程序并附加到内核事件
  - 从 eBPF 映射读取数据
  - 将数据转换为 Prometheus 指标格式

  3.Prometheus 指标：
  - process_network_bytes_total：按进程和协议分类的网络流量字节数
  - process_network_packets_total：按进程和协议分类的网络数据包数
  - process_network_connections：按进程和协议分类的网络连接状态

## 部署到Prometheus运行
在 Prometheus 配置文件 (prometheus.yml) 中添加：
```yaml
scrape_configs:
  - job_name: 'ebpf-net-exporter'
    static_configs:
      - targets: ['localhost:9101']
```

## 注意事项
1.需要 root 权限或 CAP_BPF/CAP_PERFMON 能力

2.不同内核版本可能需要调整 eBPF 程序

3.生产环境建议添加更完善的错误处理和资源管理

4.高流量场景下可能需要优化性能

这个 exporter 提供了比传统基于 /proc 的监控工具更高效、更实时的网络流量监控能力，特别适合对性能敏感的生产环境。
