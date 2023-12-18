package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

const (
	CFURL      = "wss://"
	ConfigPath = "./config.json"
)

type Config struct {
	Domain   string   `json:"domain"`
	Password string   `json:"psw"`
	SocksPort int      `json:"sport"`
	SocksBind string   `json:"sbind"`
	WebSocketURL string `json:"wkip"`
	UseIP       bool   `json:"byip"`
	CFHosts     []string `json:"cfhs"`
}

type AddrInfo struct {
	CF    bool
	IP    string
}

var (
	CFDomains = []string{}
	CIDR4     = []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"}
	CIDR6     = []string{"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32"}

	Addr4 []AddrInfo
	Addr6 []AddrInfo

	Cache      = make(map[string]AddrInfo)
	CacheMutex sync.Mutex
)

func init() {
	for _, cidr := range CIDR4 {
		addr, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("Error parsing CIDR: %v", err)
		}
		Addr4 = append(Addr4, AddrInfo{IP: addr.String(), CF: true})
		ones, _ := ipNet.Mask.Size()
		mask := net.CIDRMask(ones, 32)
		for ip := addr.Mask(mask); ipNet.Contains(ip); inc(ip) {
			Addr4 = append(Addr4, AddrInfo{IP: ip.String(), CF: true})
		}
	}

	for _, cidr := range CIDR6 {
		addr, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("Error parsing CIDR: %v", err)
		}
		Addr6 = append(Addr6, AddrInfo{IP: addr.String(), CF: true})
		ones, _ := ipNet.Mask.Size()
		mask := net.CIDRMask(ones, 128)
		for ip := addr.Mask(mask); ipNet.Contains(ip); incV6(ip) {
			ipv6 := fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s", ip[0:4], ip[4:8], ip[8:12], ip[12:16], ip[16:20], ip[20:24], ip[24:28], ip[28:32])
			Addr6 = append(Addr6, AddrInfo{IP: ipv6, CF: true})
		}
	}
}

func main() {
	config, err := loadConfig(ConfigPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	CFDomains = config.CFHosts

	http.HandleFunc("/dns-query", dnsHandler)

	go http.ListenAndServe(":8080", nil)

	socks(config)
}

func loadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func socks(config *Config) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("Error upgrading WebSocket connection: %v", err)
			return
		}

		go handleWebSocket(conn, config)
	})

	addr := fmt.Sprintf("%s:%d", config.SocksBind, config.SocksPort)
	log.Printf("Socks server listening on %s", addr)
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatalf("Error starting Socks server: %v", err)
	}
}

func handleWebSocket(conn *websocket.Conn, config *Config) {
	defer conn.Close()

	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Error reading WebSocket message: %v", err)
			return
		}

		if messageType == websocket.TextMessage {
			request := make(map[string]interface{})
			err = json.Unmarshal(message, &request)
			if err != nil {
				log.Printf("Error decoding JSON: %v", err)
				continue
			}

			hostname, ok := request["hostname"].(string)
			if !ok {
				log.Println("Invalid hostname received")
				continue
			}

			port, ok := request["port"].(float64)
			if !ok {
				log.Println("Invalid port received")
				continue
			}

			err = connectSocks(conn, hostname, int(port), config)
			if err != nil {
				log.Printf("Error connecting to remote server: %v", err)
				errMsg := map[string]interface{}{"error": "connection failed"}
				errBytes, _ := json.Marshal(errMsg)
				conn.WriteMessage(websocket.TextMessage, errBytes)
			}
		}
	}
}

func connectSocks(conn *websocket.Conn, hostname string, port int, config *Config) error {
	isCFIP, err := isCloudflareIP(hostname, config.UseIP)
	if err != nil {
		return err
	}

	if isCFIP.CF && !config.UseIP {
		ip := isCFIP.IP
		remoteConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
		if err != nil {
			return err
		}

		go pipeSockets(conn, remoteConn)
	} else {
		wsURL := fmt.Sprintf("%s%s/ws", CFURL, config.Domain)
		wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			return err
		}

		request := map[string]interface{}{
			"hostname": hostname,
			"port":     port,
			"psw":      config.Password,
		}

		reqBytes, _ := json.Marshal(request)
		wsConn.WriteMessage(websocket.TextMessage, reqBytes)

		go pipeSockets(conn, wsConn)
	}

	return nil
}

func pipeSockets(src, dest net.Conn) {
	defer src.Close()
	defer dest.Close()

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(dest, src)
		if err != nil {
			log.Printf("Error while copying data from client to server: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(src, dest)
		if err != nil {
			log.Printf("Error while copying data from server to client: %v", err)
		}
	}()

	wg.Wait()
}

func dnsHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	name := query.Get("name")
	t := query.Get("type")

	if name == "" || t != "A" {
		http.Error(w, "Invalid DNS query", http.StatusBadRequest)
		return
	}

	ip, err := dnsLookup(name)
	if err != nil {
		http.Error(w, "No IPv4 address found", http.StatusNotFound)
		return
	}

	ipBytes := net.ParseIP(ip).To4()
	if ipBytes == nil {
		http.Error(w, "No IPv4 address found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"Status": 0,
		"Answer": []map[string]interface{}{
			{"data": ip},
		},
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Error creating DNS response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(responseBytes)
}

func dnsLookup(host string) (string, error) {
	url := fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=A", host)
	response, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	var result struct {
		Status int              `json:"Status"`
		Answer []dnsAnswerEntry `json:"Answer"`
	}

	err = json.Unmarshal(data, &result)
	if err != nil {
		return "", err
	}

	if result.Status == 0 && len(result.Answer) > 0 {
		for _, entry := range result.Answer {
			if entry.Data != "" && isValidIPv4(entry.Data) {
				return entry.Data, nil
			}
		}
	}

	return "", errors.New("no IPv4 address")
}

func isCloudflareIP(host string, useIP bool) (AddrInfo, error) {
	if contains(CFDomains, host) {
		return AddrInfo{CF: true, IP: host}, nil
	}

	CacheMutex.Lock()
	info, ok := Cache[host]
	CacheMutex.Unlock()

	if !ok {
		var addrInfo AddrInfo
		if useIP || !strings.Contains(host, ":") {
			addrInfo = ipInCFCidr(host)
		} else {
			ip, err := dnsLookup(host)
			if err != nil {
				return AddrInfo{CF: false, IP: host}, nil
			}
			addrInfo = ipInCFCidr(ip)
		}

		CacheMutex.Lock()
		Cache[host] = addrInfo
		CacheMutex.Unlock()

		return addrInfo, nil
	}

	return info, nil
}

func ipInCFCidr(ip string) AddrInfo {
	isIPv6 := strings.Contains(ip, ":")

	var addrList []AddrInfo
	if isIPv6 {
		addrList = Addr6
	} else {
		addrList = Addr4
	}

	var matched AddrInfo
	matched.IP = ip

	for _, addr := range addrList {
		if isIPv6 {
			if strings.HasPrefix(ip, addr.IP) {
				matched = addr
				break
			}
		} else {
			maskedIP := applySubnetMask(ip, addr.IP)
			if maskedIP == addr.IP {
				matched = addr
				break
			}
		}
	}

	return matched
}

func applySubnetMask(ip, subnet string) string {
	ipBytes := net.ParseIP(ip).To4()
	if ipBytes == nil {
		return ""
	}

	subnetBytes := net.ParseIP(subnet).To4()
	if subnetBytes == nil {
		return ""
	}

	ipInt := ipToInt(ipBytes)
	subnetInt := ipToInt(subnetBytes)
	maskedInt := ipInt & subnetInt

	return intToIP(maskedInt)
}

func ipToInt(ip net.IP) uint32 {
	bits := ip.To4()
	return (uint32(bits[0]) << 24) | (uint32(bits[1]) << 16) | (uint32(bits[2]) << 8) | uint32(bits[3])
}

func intToIP(i uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", i>>24&255, i>>16&255, i>>8&255, i&255)
}

func contains(list []string, item string) bool {
	for _, val := range list {
		if val == item {
			return true
		}
	}
	return false
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func incV6(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

type dnsAnswerEntry struct {
	Data string `json:"data"`
}

func isValidIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if !isValidIPv4Part(part) {
			return false
		}
	}

	return true
}

func isValidIPv4Part(part string) bool {
	value := 0
	for _, ch := range part {
		digit := int(ch - '0')
		value = value*10 + digit
	}

	return value >= 0 && value <= 255
}