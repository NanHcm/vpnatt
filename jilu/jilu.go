package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	interfaces = flag.String("i", "", "逗号分隔的网卡列表")
	dnsFile    = flag.String("f", "dns.txt", "DNS域名列表文件路径")
)

var (
	logFile    *os.File
	currentDay string
	logMutex   sync.Mutex
)

type domainSet struct {
	sync.RWMutex
	patterns []string
}

func loadDomains(filename string) (*domainSet, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ds := &domainSet{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pattern := strings.ToLower(fields[1])
			ds.patterns = append(ds.patterns, pattern)
		}
	}
	return ds, scanner.Err()
}

func (ds *domainSet) contains(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	ds.RLock()
	defer ds.RUnlock()

	for _, pattern := range ds.patterns {
		if strings.HasPrefix(pattern, ".") {
			if strings.HasSuffix(domain, pattern) {
				return true
			}
		} else {
			if matchDomain(domain, pattern) {
				return true
			}
		}
	}
	return false
}

func matchDomain(domain, pattern string) bool {
	domainParts := strings.Split(domain, ".")
	patternParts := strings.Split(pattern, ".")

	dLen := len(domainParts)
	pLen := len(patternParts)

	if pLen > dLen {
		return false
	}

	for i := 0; i < pLen; i++ {
		idx := dLen - pLen + i
		if domainParts[idx] != patternParts[i] {
			return false
		}
	}
	return true
}

func writeLog(t time.Time, domain string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	day := t.Format("20060102")
	if day != currentDay || logFile == nil {
		if logFile != nil {
			logFile.Close()
		}

		filename := fmt.Sprintf("dns_hit_%s.log", day)
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("创建日志文件失败: %v", err)
			return
		}
		logFile = f
		currentDay = day
	}

	logLine := fmt.Sprintf("[%s][%s---命中]\n",
		t.Format("2006-01-02 15:04:05"), domain)
	if _, err := logFile.WriteString(logLine); err != nil {
		log.Printf("写入日志失败: %v", err)
	}
}

func capture(iface string, ds *domainSet) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("打开网卡 %s 失败: %v", iface, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp and port 53"); err != nil {
		log.Printf("设置过滤器失败: %v", err)
		return
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			continue
		}

		dns, _ := dnsLayer.(*layers.DNS)
		if !dns.QR && dns.OpCode == layers.DNSOpCodeQuery {
			for _, q := range dns.Questions {
				domain := string(q.Name)
				domain = strings.TrimSuffix(domain, ".")
				if ds.contains(domain) {
					now := time.Now()
					log.Printf("命中域名: %s", domain)
					writeLog(now, domain)
				}
			}
		}
	}
}

func main() {
	flag.Parse()

	if *interfaces == "" {
		log.Fatal("必须使用 -i 参数指定至少一个网卡")
	}

	ds, err := loadDomains(*dnsFile)
	if err != nil {
		log.Fatalf("加载DNS文件失败: %v", err)
	}

	ifaces := strings.Split(*interfaces, ",")
	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		go func(iface string) {
			defer wg.Done()
			capture(iface, ds)
		}(iface)
	}
	wg.Wait()
}