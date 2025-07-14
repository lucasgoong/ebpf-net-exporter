package bpf

import (
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Module 封装eBPF模块
type Module struct {
	objs        netstatsObjects
	links       []link.Link
	pidFilter   *ebpf.Map
	flowStats   *ebpf.Map
	tcpConns    *ebpf.Map
	udpConns    *ebpf.Map
}

// 对应eBPF程序中的maps和programs
type netstatsObjects struct {
	PidFilter     *ebpf.Map `ebpf:"pid_filter"`
	FlowStats     *ebpf.Map `ebpf:"flow_stats"`
	TcpConnections *ebpf.Map `ebpf:"tcp_connections"`
	UdpConnections *ebpf.Map `ebpf:"udp_connections"`

	SkbTxTracepoint *ebpf.Program `ebpf:"tracepoint_skb_skb_tx"`
	SkbRxTracepoint *ebpf.Program `ebpf:"tracepoint_skb_skb_rx"`
	TcpStateKprobe  *ebpf.Program `ebpf:"kprobe_tcp_set_state"`
}

// InitEbpfModule 初始化eBPF模块
func InitEbpfModule(processNames []string) (*Module, error) {
	// 提高资源限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("移除内存锁失败: %w", err)
	}

	// 加载eBPF程序
	spec, err := ebpf.LoadCollectionSpec("bpf/netstats.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("加载eBPF程序规范失败: %w", err)
	}

	// 应用全局常量替换
	for _, prog := range spec.Programs {
		prog.Constants["TARGET_PID"] = getTargetPIDs(processNames)
	}

	var objs netstatsObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("加载eBPF程序失败: %w", err)
	}

	// 附加跟踪点
	txLink, err := link.Tracepoint("skb", "skb_tx", objs.SkbTxTracepoint, nil)
	if err != nil {
		return nil, fmt.Errorf("附加skb_tx跟踪点失败: %w", err)
	}

	rxLink, err := link.Tracepoint("skb", "skb_rx", objs.SkbRxTracepoint, nil)
	if err != nil {
		txLink.Close()
		return nil, fmt.Errorf("附加skb_rx跟踪点失败: %w", err)
	}

	// 附加kprobe
	tcpStateLink, err := link.Kprobe("tcp_set_state", objs.TcpStateKprobe, nil)
	if err != nil {
		txLink.Close()
		rxLink.Close()
		return nil, fmt.Errorf("附加tcp_set_state kprobe失败: %w", err)
	}

	module := &Module{
		objs:        objs,
		links:       []link.Link{txLink, rxLink, tcpStateLink},
		pidFilter:   objs.PidFilter,
		flowStats:   objs.FlowStats,
		tcpConns:    objs.TcpConnections,
		udpConns:    objs.UdpConnections,
	}

	// 填充PID过滤列表
	if err := module.populatePidFilter(processNames); err != nil {
		module.Close()
		return nil, fmt.Errorf("填充PID过滤列表失败: %w", err)
	}

	return module, nil
}

// 关闭资源
func (m *Module) Close() {
	for _, link := range m.links {
		link.Close()
	}
	m.objs.Close()
}

// 填充PID过滤映射
func (m *Module) populatePidFilter(processNames []string) error {
	pids := getTargetPIDs(processNames)
	for _, pid := range pids {
		var exists uint8 = 1
		if err := m.pidFilter.Put(uint32(pid), exists); err != nil {
			return fmt.Errorf("添加PID %d到过滤列表失败: %w", pid, err)
		}
	}
	return nil
}

// 获取目标进程的PID
func getTargetPIDs(processNames []string) []int {
	var pids []int
	// 实际实现需要遍历/proc目录，查找匹配的进程名
	// 简化示例，这里假设已经获取了PID列表
	return pids
}

// 获取所有流量统计
func (m *Module) GetAllFlowStats() (map[FlowKey]FlowStats, error) {
	stats := make(map[FlowKey]FlowStats)
	iter := m.flowStats.Iterate()

	var key FlowKey
	var value FlowStats

	for iter.Next(unsafe.Pointer(&key), unsafe.Pointer(&value)) {
		stats[key] = value
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("读取流量统计失败: %w", err)
	}

	return stats, nil
}

// FlowKey 对应eBPF中的flow_key
type FlowKey struct {
	PID      uint32
	Protocol uint8
}

// FlowStats 对应eBPF中的flow_stats
type FlowStats struct {
	RxPackets uint64
	RxBytes   uint64
	TxPackets uint64
	TxBytes   uint64
}
