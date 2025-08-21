package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// 用于跟踪每个源IP的数据包计数和时间
type ipStats struct {
	packetCount int
	firstSeen   time.Time
	lastSeen    time.Time
}

// 配置参数
const (
	maxPacketsPerSecond = 100 // 每秒最大数据包数
	blockDuration       = 60  // 阻塞时间(秒)
)

var (
	ipCounters = make(map[string]*ipStats)
	mu         sync.Mutex
	blockedIPs = make(map[string]time.Time)
)

func main() {
	// 自动选择合适的网络接口
	device, err := selectBestInterface()
	if err != nil {
		log.Fatalf("无法选择合适的网络接口: %v", err)
	}

	fmt.Printf("已选择网络接口: %s (%s)\n", device.Name, device.Description)

	// 打开网络接口进行监听
	handle, err := pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("无法打开网络接口: %v", err)
	}
	defer handle.Close()

	fmt.Printf("开始监听接口 %s...\n", device.Name)

	// 设置数据包捕获循环
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

// 自动选择最佳网络接口
func selectBestInterface() (pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, err
	}

	// 优先选择有IPv4地址且非本地回环的接口
	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			if ipnet, ok := addr.IPNet.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil { // 检查是否为IPv4地址
					return dev, nil
				}
			}
		}
	}

	// 如果没有找到IPv4接口，尝试返回第一个可用接口
	if len(devices) > 0 {
		return devices[0], nil
	}

	return pcap.Interface{}, fmt.Errorf("没有找到可用的网络接口")
}

// 处理捕获到的数据包
func processPacket(packet gopacket.Packet) {
	// 提取网络层
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return // 没有网络层信息
	}

	srcIP := networkLayer.NetworkFlow().Src().String()
	
	// 检查IP是否被阻塞
	mu.Lock()
	if unblockTime, blocked := blockedIPs[srcIP]; blocked {
		if time.Now().Before(unblockTime) {
			mu.Unlock()
			return // 忽略被阻塞IP的数据包
		}
		// 解除阻塞
		delete(blockedIPs, srcIP)
		fmt.Printf("已解除对 %s 的阻塞\n", srcIP)
	}
	mu.Unlock()

	// 更新IP统计信息
	mu.Lock()
	stats, exists := ipCounters[srcIP]
	if !exists {
		stats = &ipStats{
			packetCount: 1,
			firstSeen:   time.Now(),
			lastSeen:    time.Now(),
		}
		ipCounters[srcIP] = stats
	} else {
		stats.packetCount++
		stats.lastSeen = time.Now()
	}
	
	// 检查是否超过速率限制
	duration := stats.lastSeen.Sub(stats.firstSeen).Seconds()
	if duration >= 1 { // 至少观察1秒
		packetsPerSecond := float64(stats.packetCount) / duration
		if packetsPerSecond > maxPacketsPerSecond {
			blockedIPs[srcIP] = time.Now().Add(time.Second * blockDuration)
			fmt.Printf("检测到可能的Flood攻击! 已阻塞 %s (%.2f 包/秒)\n", 
				srcIP, packetsPerSecond)
			// 重置计数器
			delete(ipCounters, srcIP)
		} else if duration > 5 { // 每5秒重置一次计数器，避免长期累积
			stats.packetCount = 0
			stats.firstSeen = time.Now()
		}
	}
	mu.Unlock()

	// 打印数据包信息 (可选)
	printPacketInfo(packet)
}

// 打印数据包基本信息
func printPacketInfo(packet gopacket.Packet) {
	// 获取以太网层
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		fmt.Printf("源MAC: %s  目的MAC: %s  ", eth.SrcMAC, eth.DstMAC)
	}

	// 获取网络层
	netLayer := packet.Layer(layers.LayerTypeIPv4)
	if netLayer != nil {
		ip, _ := netLayer.(*layers.IPv4)
		fmt.Printf("源IP: %s  目的IP: %s  协议: %s\n", 
			ip.SrcIP, ip.DstIP, ip.Protocol)
	}
}
    