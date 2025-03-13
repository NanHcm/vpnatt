package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"crypto/tls"

	"github.com/miekg/dns"
)

const (
	LogDir      = "/var/log/cxon"
	DNSRuleFile = "dns.txt"
)

type Rule struct {
	Pattern string
	IP      net.IP
}

var (
	rules     []Rule
	logFile   *os.File
	logDate   string
	logMutex  sync.Mutex
	ruleMutex sync.RWMutex
)

func initLogSystem() error {
	// 创建日志目录
	if err := os.MkdirAll(LogDir, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %v", err)
	}

	// 验证目录可写性
	testFile := filepath.Join(LogDir, "write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("目录不可写: %v", err)
	}
	os.Remove(testFile)

	// 初始化当日日志文件
	now := time.Now()
	logDate = now.Format("20060102")
	filename := filepath.Join(LogDir, logDate+".txt")

	var err error
	logFile, err = os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("创建日志文件失败: %v", err)
	}

	return nil
}

func logHijacked(domain string) {
	now := time.Now()
	date := now.Format("20060102")
	timestamp := now.Format("2006-01-02 15:04:05")

	logMutex.Lock()
	defer logMutex.Unlock()

	// 跨天切换日志文件
	if date != logDate {
		filename := filepath.Join(LogDir, date+".txt")
		newFile, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("创建新日志文件失败: %v\n", err)
			return
		}

		oldFile := logFile
		logFile = newFile
		logDate = date
		oldFile.Close()
	}

	// 写入日志
	logEntry := fmt.Sprintf("[%s] HIJACKED %s\n", timestamp, domain)
	if _, err := logFile.WriteString(logEntry); err != nil {
		fmt.Printf("日志写入失败: %v\n", err)
	}
	fmt.Print(logEntry) // 控制台输出
}

func loadRules() error {
	file, err := os.Open(DNSRuleFile)
	if err != nil {
		return err
	}
	defer file.Close()

	newRules := []Rule{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		ip := net.ParseIP(parts[0])
		if ip == nil {
			continue
		}

		newRules = append(newRules, Rule{
			Pattern: strings.ToLower(parts[1]),
			IP:      ip,
		})
	}

	ruleMutex.Lock()
	rules = newRules
	ruleMutex.Unlock()

	return scanner.Err()
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if len(r.Question) == 0 {
		return
	}

	q := r.Question[0]
	if q.Qtype != dns.TypeA {
		forwardQuery(w, r)
		return
	}

	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	ruleMutex.RLock()
	defer ruleMutex.RUnlock()

	for _, rule := range rules {
		if strings.Contains(domain, rule.Pattern) {
			logHijacked(domain)
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: rule.IP,
			}
			m.Answer = append(m.Answer, rr)
			w.WriteMsg(m)
			return
		}
	}

	forwardQuery(w, r)
}

func forwardQuery(w dns.ResponseWriter, r *dns.Msg) {
    c := &dns.Client{
        Net:          "tcp",
        Timeout:      5 * time.Second,
        SingleInflight: true,  // 防止重复查询
        TLSConfig:    &tls.Config{InsecureSkipVerify: true}, // 如需DoH可启用
    }

    // 优先选择EDNS0
    r = r.Copy()
    r.SetEdns0(4096, false)

    // 多上游容灾
    upstreams := []string{"8.8.8.8:53", "1.1.1.1:53", "208.67.222.222:53"}
    var err error
    var resp *dns.Msg
    
    for _, server := range upstreams {
        resp, _, err = c.Exchange(r, server)
        if err == nil {
            break
        }
        fmt.Printf("服务器 %s 查询失败: %v\n", server, err)
    }

    if err != nil {
        fmt.Printf("所有上游均失败: %v\n", err)
        m := new(dns.Msg)
        m.SetRcode(r, dns.RcodeServerFailure)
        w.WriteMsg(m)
        return
    }
    
    if err := w.WriteMsg(resp); err != nil {
        fmt.Printf("响应回写错误: %v\n", err)
    }
}

func setupIPTables() error {
	cmd := exec.Command("iptables",
		"-t", "nat",
		"-A", "OUTPUT",
		"-p", "udp",
		"--dport", "53",
		"-j", "REDIRECT",
		"--to-port", "53",
	)
	return cmd.Run()
}

func cleanupIPTables() {
	cmd := exec.Command("iptables",
		"-t", "nat",
		"-D", "OUTPUT",
		"-p", "udp",
		"--dport", "53",
		"-j", "REDIRECT",
		"--to-port", "53",
	)
	cmd.Run()
}

func main() {
	// 初始化日志系统
	if err := initLogSystem(); err != nil {
		fmt.Printf("初始化失败: %s\n", err)
		fmt.Println("请使用root权限运行")
		os.Exit(1)
	}
	defer logFile.Close()

	// 加载DNS规则
	if err := loadRules(); err != nil {
		fmt.Printf("加载规则失败: %v\n", err)
		os.Exit(1)
	}

	// 配置网络
	if err := setupIPTables(); err != nil {
		fmt.Printf("配置iptables失败: %v\n", err)
		os.Exit(1)
	}
	defer cleanupIPTables()

	// 信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n收到退出信号，清理中...")
		cleanupIPTables()
		logFile.Close()
		os.Exit(0)
	}()

	// 启动DNS服务器
	dns.HandleFunc(".", handleDNSRequest)
	server := &dns.Server{Addr: ":53", Net: "udp"}
	fmt.Println("DNS劫持服务已启动 (端口:53)")

	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("服务器错误: %v\n", err)
		cleanupIPTables()
		os.Exit(1)
	}
}