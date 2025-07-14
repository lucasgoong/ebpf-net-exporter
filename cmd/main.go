package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"ebpf-net-exporter/internal/config"
	"ebpf-net-exporter/internal/collector"
	"ebpf-net-exporter/internal/bpf"
)

func main() {
	configPath := flag.String("config", "config/processes.conf", "配置文件路径")
	listenAddr := flag.String("listen", ":9101", "监听地址")
	flag.Parse()

	// 加载配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 初始化eBPF程序
	ebpfModule, err := bpf.InitEbpfModule(cfg.Processes)
	if err != nil {
		log.Fatalf("初始化eBPF模块失败: %v", err)
	}
	defer ebpfModule.Close()

	// 创建指标收集器
	netCollector := collector.NewNetworkCollector(ebpfModule)
	prometheus.MustRegister(netCollector)

	// 启动HTTP服务器
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
			<head><title>eBPF Network Exporter</title></head>
			<body>
				<h1>eBPF Network Exporter</h1>
				<p><a href="/metrics">Metrics</a></p>
			</body>
		</html>`))
	})

	go func() {
		log.Printf("服务器监听在 %s", *listenAddr)
		if err := http.ListenAndServe(*listenAddr, nil); err != nil {
			log.Fatalf("启动HTTP服务器失败: %v", err)
		}
	}()

	// 处理信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("按 Ctrl+C 退出")
	<-sigCh
	fmt.Println("正在优雅退出...")
}
