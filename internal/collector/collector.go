package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"ebpf-net-exporter/internal/bpf"
)

// NetworkCollector 收集网络指标
type NetworkCollector struct {
	ebpfModule *bpf.Module

	// 定义Prometheus指标
	bytesCounter *prometheus.CounterVec
	packetsCounter *prometheus.CounterVec
	connectionsGauge *prometheus.GaugeVec

	// 用于缓存上一次的值，计算差值
	lastStats map[bpf.FlowKey]bpf.FlowStats
	mu        sync.RWMutex
}

// NewNetworkCollector 创建新的网络指标收集器
func NewNetworkCollector(ebpfModule *bpf.Module) *NetworkCollector {
	c := &NetworkCollector{
		ebpfModule: ebpfModule,
		lastStats:  make(map[bpf.FlowKey]bpf.FlowStats),
	}

	// 初始化Prometheus指标
	c.bytesCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "process_network_bytes_total",
			Help: "Total network bytes by process and protocol",
		},
		[]string{"pid", "protocol", "direction"},
	)

	c.packetsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "process_network_packets_total",
			Help: "Total network packets by process and protocol",
		},
		[]string{"pid", "protocol", "direction"},
	)

	c.connectionsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "process_network_connections",
			Help: "Current network connections by process and protocol",
		},
		[]string{"pid", "protocol", "local_addr", "local_port", "remote_addr", "remote_port", "state"},
	)

	// 注册指标
	prometheus.MustRegister(c.bytesCounter)
	prometheus.MustRegister(c.packetsCounter)
	prometheus.MustRegister(c.connectionsGauge)

	// 启动定期收集
	go c.startPeriodicCollection()

	return c
}

// 启动定期收集
func (c *NetworkCollector) startPeriodicCollection() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.collect(); err != nil {
				fmt.Printf("收集指标失败: %v\n", err)
			}
		case <-context.Background().Done():
			return
		}
	}
}

// 收集指标
func (c *NetworkCollector) collect() error {
	// 从eBPF获取最新统计
	stats, err := c.ebpfModule.GetAllFlowStats()
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 计算增量并更新指标
	for key, current := range stats {
		last, exists := c.lastStats[key]

		// 计算差值（只在第二次及以后计算）
		if exists {
			// 更新字节计数器
			c.bytesCounter.WithLabelValues(
				fmt.Sprintf("%d", key.PID),
				protocolToString(key.Protocol),
				"rx",
			).Add(float64(current.RxBytes - last.RxBytes))

			c.bytesCounter.WithLabelValues(
				fmt.Sprintf("%d", key.PID),
				protocolToString(key.Protocol),
				"tx",
			).Add(float64(current.TxBytes - last.TxBytes))

			// 更新包计数器
			c.packetsCounter.WithLabelValues(
				fmt.Sprintf("%d", key.PID),
				protocolToString(key.Protocol),
				"rx",
			).Add(float64(current.RxPackets - last.RxPackets))

			c.packetsCounter.WithLabelValues(
				fmt.Sprintf("%d", key.PID),
				protocolToString(key.Protocol),
				"tx",
			).Add(float64(current.TxPackets - last.TxPackets))
		}

		// 更新缓存
		c.lastStats[key] = current
	}

	// 收集连接信息
	// ... 代码省略

	return nil
}

// 实现prometheus.Collector接口
func (c *NetworkCollector) Describe(ch chan<- *prometheus.Desc) {
	c.bytesCounter.Describe(ch)
	c.packetsCounter.Describe(ch)
	c.connectionsGauge.Describe(ch)
}

func (c *NetworkCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	c.bytesCounter.Collect(ch)
	c.packetsCounter.Collect(ch)
	c.connectionsGauge.Collect(ch)
}

// 将协议号转换为字符串
func protocolToString(protocol uint8) string {
	switch protocol {
	case 6:  // IPPROTO_TCP
		return "tcp"
	case 17: // IPPROTO_UDP
		return "udp"
	default:
		return fmt.Sprintf("unknown_%d", protocol)
	}
}
