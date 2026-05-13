package main

/*
Purpose: 高并发端口扫描器
         支持：TCP/UDP 扫描、服务识别、并发控制、输出报告
Auth: 仅限授权使用 — 未经书面授权禁止对任何目标执行扫描
Usage:
    go run port_scanner.go -t 192.168.1.1 -p 1-65535
    go run port_scanner.go -t 192.168.1.0/24 -p 22,80,443,3306 --output report.json
*/

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================
// 配置与数据结构
// ============================================================

type Config struct {
	Target      string
	Ports       string
	Timeout     time.Duration
	Concurrency int
	Output      string
	UDP         bool
	BannerGrab  bool
}

type ScanResult struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	State      string `json:"state"`
	Service    string `json:"service,omitempty"`
	Banner     string `json:"banner,omitempty"`
	Latency    int    `json:"latency_ms"`
	Timestamp  string `json:"timestamp"`
}

type ServiceFingerprint struct {
	PortPattern string
	ServiceName string
	BannerMatch string
}

// ============================================================
// 服务指纹数据库
// ============================================================

var serviceFingerprints = []ServiceFingerprint{
	{PortPattern: "^21$", ServiceName: "ftp", BannerMatch: "FTP|220"},
	{PortPattern: "^22$", ServiceName: "ssh", BannerMatch: "SSH|OpenSSH"},
	{PortPattern: "^23$", ServiceName: "telnet", BannerMatch: "Telnet"},
	{PortPattern: "^25$", ServiceName: "smtp", BannerMatch: "SMTP|220|ESMTP"},
	{PortPattern: "^53$", ServiceName: "dns", BannerMatch: "DNS"},
	{PortPattern: "^67$", ServiceName: "dhcp", BannerMatch: "DHCP"},
	{PortPattern: "^68$", ServiceName: "dhcp", BannerMatch: "DHCP"},
	{PortPattern: "^80$", ServiceName: "http", BannerMatch: "HTTP|HTML"},
	{PortPattern: "^110$", ServiceName: "pop3", BannerMatch: "POP3"},
	{PortPattern: "^143$", ServiceName: "imap", BannerMatch: "IMAP"},
	{PortPattern: "^161$", ServiceName: "snmp", BannerMatch: "SNMP"},
	{PortPattern: "^443$", ServiceName: "https", BannerMatch: "HTTP|HTML|SSL|TLS"},
	{PortPattern: "^445$", ServiceName: "smb", BannerMatch: "SMB"},
	{PortPattern: "^993$", ServiceName: "imaps", BannerMatch: "IMAP|SSL"},
	{PortPattern: "^995$", ServiceName: "pop3s", BannerMatch: "POP3|SSL"},
	{PortPattern: "^3306$", ServiceName: "mysql", BannerMatch: "MySQL|mariadb"},
	{PortPattern: "^3389$", ServiceName: "rdp", BannerMatch: "RDP"},
	{PortPattern: "^5432$", ServiceName: "postgresql", BannerMatch: "PostgreSQL"},
	{PortPattern: "^5900$", ServiceName: "vnc", BannerMatch: "RFB|VNC"},
	{PortPattern: "^6379$", ServiceName: "redis", BannerMatch: "redis"},
	{PortPattern: "^8000$", ServiceName: "http-proxy", BannerMatch: "HTTP|HTML"},
	{PortPattern: "^8080$", ServiceName: "http-alt", BannerMatch: "HTTP|HTML"},
	{PortPattern: "^8443$", ServiceName: "https-alt", BannerMatch: "HTTP|HTML|SSL|TLS"},
	{PortPattern: "^9200$", ServiceName: "elasticsearch", BannerMatch: "Elasticsearch"},
	{PortPattern: "^11211$", ServiceName: "memcached", BannerMatch: "memcached"},
	{PortPattern: "^27017$", ServiceName: "mongodb", BannerMatch: "MongoDB"},
	{PortPattern: "^27018$", ServiceName: "mongodb-shard", BannerMatch: "MongoDB"},
}

// ============================================================
// 扫描器核心
// ============================================================

type PortScanner struct {
	config    Config
	results   []ScanResult
	mu        sync.Mutex
	wg        sync.WaitGroup
	semaphore chan struct{}
}

func NewScanner(config Config) *PortScanner {
	return &PortScanner{
		config:    config,
		semaphore: make(chan struct{}, config.Concurrency),
	}
}

func (s *PortScanner) Scan(targets []string, ports []int) []ScanResult {
	s.wg.Add(len(targets) * len(ports))

	for _, target := range targets {
		for _, port := range ports {
			go s.scanPort(target, port)
		}
	}

	s.wg.Wait()
	return s.results
}

func (s *PortScanner) scanPort(host string, port int) {
	defer s.wg.Done()
	s.semaphore <- struct{}{}
	defer func() { <-s.semaphore }()

	startTime := time.Now()
	result := ScanResult{
		Host:      host,
		Port:      port,
		Protocol:  "tcp",
		State:     "closed",
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
	}

	var conn net.Conn
	var err error

	if s.config.UDP {
		conn, err = net.DialTimeout("udp", fmt.Sprintf("%s:%d", host, port), s.config.Timeout)
	} else {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), s.config.Timeout)
	}

	result.Latency = int(time.Since(startTime).Milliseconds())

	if err == nil {
		result.State = "open"
		defer conn.Close()

		// 服务识别
		if s.config.BannerGrab {
			service, banner := s.grabBanner(conn, port)
			result.Service = service
			result.Banner = banner
		} else {
			result.Service = s.identifyService(port)
		}
	}

	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()
}

func (s *PortScanner) grabBanner(conn net.Conn, port int) (string, string) {
	// 设置读写超时
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// 尝试发送探测包
	probes := map[int]string{
		21:  "\r\n",
		22:  "SSH-2.0-Scanner\r\n",
		25:  "EHLO scanner\r\n",
		80:  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		110: "USER test\r\n",
		143: "A001 CAPABILITY\r\n",
		3306: "",
		5432: "",
		6379: "PING\r\n",
	}

	var banner string
	service := s.identifyService(port)

	if probe, ok := probes[port]; ok {
		if probe != "" {
			conn.Write([]byte(probe))
		}

		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err == nil {
			banner = strings.TrimSpace(line)
		}
	}

	// 使用指纹匹配
	for _, fp := range serviceFingerprints {
		matched, _ := regexp.MatchString(fp.PortPattern, strconv.Itoa(port))
		if matched {
			if fp.BannerMatch != "" {
				re, _ := regexp.Compile(fp.BannerMatch)
				if re.MatchString(banner) {
					service = fp.ServiceName
					break
				}
			} else {
				service = fp.ServiceName
				break
			}
		}
	}

	return service, banner
}

func (s *PortScanner) identifyService(port int) string {
	portStr := strconv.Itoa(port)
	for _, fp := range serviceFingerprints {
		matched, _ := regexp.MatchString(fp.PortPattern, portStr)
		if matched {
			return fp.ServiceName
		}
	}
	return "unknown"
}

func (s *PortScanner) PrintResults() {
	if len(s.results) == 0 {
		fmt.Println("\n[-] 未发现开放端口")
		return
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Println("  端口扫描报告")
	fmt.Printf("%s\n", strings.Repeat("=", 60))

	for _, r := range s.results {
		if r.State == "open" {
			status := "OPEN"
			fmt.Printf("\n  [%s] %s:%d (%s)", status, r.Host, r.Port, r.Protocol)
			fmt.Printf("\n  服务: %s", r.Service)
			if r.Banner != "" {
				fmt.Printf("\n  Banner: %s", r.Banner)
			}
			fmt.Printf("\n  延迟: %dms", r.Latency)
			fmt.Printf("\n  时间: %s", r.Timestamp)
		}
	}

	openCount := 0
	for _, r := range s.results {
		if r.State == "open" {
			openCount++
		}
	}
	fmt.Printf("\n\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("  总计: %d 个端口 | 开放: %d\n", len(s.results), openCount)
	fmt.Printf("%s\n", strings.Repeat("=", 60))
}

func (s *PortScanner) ExportJSON(filepath string) error {
	data := struct {
		Results []ScanResult `json:"results"`
		Summary struct {
			Total  int `json:"total"`
			Open   int `json:"open"`
			Closed int `json:"closed"`
		} `json:"summary"`
	}{
		Results: s.results,
	}

	for _, r := range s.results {
		data.Summary.Total++
		if r.State == "open" {
			data.Summary.Open++
		} else {
			data.Summary.Closed++
		}
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(filepath, jsonData, 0644)
}

// ============================================================
// 工具函数
// ============================================================

func parseTargets(target string) ([]string, error) {
	var targets []string

	// 检查是否是 CIDR
	if strings.Contains(target, "/") {
		// 简化处理，实际应使用 github.com/appcodelabs/cidr
		// 这里只演示单目标
		targets = append(targets, target)
		return targets, nil
	}

	// 检查是否是范围 (192.168.1.1-192.168.1.10)
	if strings.Contains(target, "-") {
		parts := strings.Split(target, "-")
		if len(parts) == 2 {
			start := strings.TrimSpace(parts[0])
			end := strings.TrimSpace(parts[1])
			targets = append(targets, start) // 简化：只扫描起始
			return targets, nil
		}
	}

	// 单个目标
	targets = append(targets, strings.TrimSpace(target))
	return targets, nil
}

func parsePorts(ports string) ([]int, error) {
	var portList []int

	parts := strings.Split(ports, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)

		// 范围 (1-100)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err1 == nil && err2 == nil {
					for p := start; p <= end; p++ {
						portList = append(portList, p)
					}
					continue
				}
			}
		}

		// 单个端口
		port, err := strconv.Atoi(part)
		if err == nil {
			portList = append(portList, port)
		}
	}

	return portList, nil
}

// ============================================================
// Main
// ============================================================

func main() {
	// 授权确认
	fmt.Println("⚠️  请确认你已获得目标的端口扫描授权")
	fmt.Print("确认已获授权？(y/N): ")
	var confirm string
	fmt.Scanln(&confirm)
	if strings.ToLower(confirm) != "y" {
		os.Exit(0)
	}

	// 解析参数
	var (
		target      = flag.String("t", "", "目标 (IP/CIDR/范围)")
		ports       = flag.String("p", "1-1024", "端口 (单个/范围/逗号分隔)")
		timeout     = flag.Int("timeout", 2, "连接超时(秒)")
		concurrency = flag.Int("c", 100, "并发数")
		output      = flag.String("o", "", "输出 JSON 文件")
		udp         = flag.Bool("udp", false, "UDP 扫描")
		banner      = flag.Bool("banner", false, "Banner 抓取")
	)
	flag.Parse()

	if *target == "" {
		fmt.Println("请指定目标: -t <target>")
		os.Exit(1)
	}

	// 解析目标和端口
	targets, err := parseTargets(*target)
	if err != nil {
		fmt.Printf("目标解析错误: %v\n", err)
		os.Exit(1)
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		fmt.Printf("端口解析错误: %v\n", err)
		os.Exit(1)
	}

	config := Config{
		Target:      *target,
		Ports:       *ports,
		Timeout:     time.Duration(*timeout) * time.Second,
		Concurrency: *concurrency,
		Output:      *output,
		UDP:         *udp,
		BannerGrab:  *banner,
	}

	// 开始扫描
	fmt.Printf("\n[*] 开始端口扫描: %s\n", *target)
	fmt.Printf("[*] 端口范围: %s (%d 个端口)\n", *ports, len(portList))
	fmt.Printf("[*] 并发数: %d\n", *concurrency)
	fmt.Printf("[*] 超时: %ds\n", *timeout)
	if *udp {
		fmt.Printf("[*] 模式: UDP\n")
	} else {
		fmt.Printf("[*] 模式: TCP\n")
	}

	scanner := NewScanner(config)
	startTime := time.Now()
	results := scanner.Scan(targets, portList)
	elapsed := time.Since(startTime)

	fmt.Printf("\n[*] 扫描完成，耗时: %v\n", elapsed)
	scanner.PrintResults()

	// 导出报告
	if *output != "" {
		err := scanner.ExportJSON(*output)
		if err != nil {
			fmt.Printf("\n[!] 报告导出失败: %v\n", err)
		} else {
			fmt.Printf("\n[+] JSON 报告已导出: %s\n", *output)
		}
	}
}
