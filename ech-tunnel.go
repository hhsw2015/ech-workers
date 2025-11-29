package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// ======================== 全局参数 ========================

var (
	listenAddr    string
	forwardAddr   string
	ipAddr        string
	certFile      string
	keyFile       string
	token         string
	cidrs         string
	connectionNum int

	// 新增 ECH/DNS 参数
	dnsServer string // -dns
	echDomain string // -ech

	// 运行期缓存的 ECHConfigList
	echListMu sync.RWMutex
	echList   []byte

	// 多通道连接池
	echPool *ECHPool
)

func init() {
	flag.StringVar(&listenAddr, "l", "", "监听地址 (tcp://监听1/目标1,监听2/目标2,... 或 ws://ip:port/path 或 wss://ip:port/path 或 proxy://[user:pass@]ip:port)")
	flag.StringVar(&forwardAddr, "f", "", "服务地址 (格式: wss://host:port/path)")
	flag.StringVar(&ipAddr, "ip", "", "指定解析的IP地址（仅客户端：将 wss 主机名定向到该 IP 连接）")
	flag.StringVar(&certFile, "cert", "", "TLS证书文件路径（默认:自动生成，仅服务端）")
	flag.StringVar(&keyFile, "key", "", "TLS密钥文件路径（默认:自动生成，仅服务端）")
	flag.StringVar(&token, "token", "", "身份验证令牌（WebSocket Subprotocol）")
	flag.StringVar(&cidrs, "cidr", "0.0.0.0/0,::/0", "允许的来源 IP 范围 (CIDR),多个范围用逗号分隔")
	flag.StringVar(&dnsServer, "dns", "dns.alidns.com/dns-query", "查询 ECH 公钥所用的 DoH 服务器地址")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "用于查询 ECH 公钥的域名")
	flag.IntVar(&connectionNum, "n", 3, "WebSocket连接数量")
}

func main() {
	flag.Parse()

	if strings.HasPrefix(listenAddr, "ws://") || strings.HasPrefix(listenAddr, "wss://") {
		runWebSocketServer(listenAddr)
		return
	}
	if strings.HasPrefix(listenAddr, "tcp://") {
		// 客户端模式：预先获取 ECH 公钥（失败则直接退出，严格禁止回退）
		if err := prepareECH(); err != nil {
			log.Fatalf("[客户端] 获取 ECH 公钥失败: %v", err)
		}
		runTCPClient(listenAddr, forwardAddr)
		return
	}
	if strings.HasPrefix(listenAddr, "proxy://") {
		// 代理模式（支持 SOCKS5 和 HTTP）：预先获取 ECH 公钥
		if err := prepareECH(); err != nil {
			log.Fatalf("[代理] 获取 ECH 公钥失败: %v", err)
		}
		runProxyServer(listenAddr, forwardAddr)
		return
	}

	log.Fatal("监听地址格式错误，请使用 ws://, wss://, tcp:// 或 proxy:// 前缀")
}

// 判断是否为正常的网络关闭错误
func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "normal closure")
}

// ======================== ECH 相关（客户端） ========================

const (
	typeHTTPS = 65 // DNS HTTPS 记录类型
)

// 客户端启动时查询 ECH 配置并缓存
func prepareECH() error {
	for {
		log.Printf("[客户端] 使用 DNS 服务器查询 ECH: %s -> %s", dnsServer, echDomain)
		echBase64, err := queryHTTPSRecord(echDomain, dnsServer)
		if err != nil {
			log.Printf("[客户端] DNS 查询失败: %v，2秒后重试...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if echBase64 == "" {
			log.Printf("[客户端] 未找到 ECH 参数（HTTPS RR key=echconfig/5），2秒后重试...")
			time.Sleep(2 * time.Second)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(echBase64)
		if err != nil {
			log.Printf("[客户端] ECH Base64 解码失败: %v，2秒后重试...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		echListMu.Lock()
		echList = raw
		echListMu.Unlock()
		log.Printf("[客户端] ECHConfigList 长度: %d 字节", len(raw))
		return nil
	}
}

// 刷新 ECH 配置（用于重试）
func refreshECH() error {
	log.Printf("[ECH] 刷新 ECH 公钥配置...")
	return prepareECH()
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH 配置尚未加载")
	}
	return echList, nil
}

func buildTLSConfigWithECH(serverName string, echList []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("加载系统根证书失败: %w", err)
	}
	tcfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		// 完全采用 ECH，禁止回退
		EncryptedClientHelloConfigList: echList,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝 ECH（禁止回退）")
		},
		RootCAs: roots,
	}
	return tcfg, nil
}

func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	dohURL := dnsServer
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	return queryDoH(domain, dohURL)
}

func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("无效的 DoH URL: %v", err)
	}
	q := u.Query()
	q.Set("name", domain)
	q.Set("type", "HTTPS")
	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)

	q.Set("dns", dnsBase64)
	// 移除 name 和 type，因为使用了 dns 参数
	q.Del("name")
	q.Del("type")

	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH 请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH 服务器返回错误: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 DoH 响应失败: %v", err)
	}

	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	// Header
	query = append(query, 0x00, 0x01)                         // ID
	query = append(query, 0x01, 0x00)                         // 标准查询
	query = append(query, 0x00, 0x01)                         // QDCOUNT = 1
	query = append(query, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // AN/NS/AR = 0
	// QNAME
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00) // root
	// QTYPE/QCLASS
	query = append(query, byte(qtype>>8), byte(qtype))
	query = append(query, 0x00, 0x01) // IN
	return query
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", fmt.Errorf("响应长度无效")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("未找到回答记录")
	}
	// 跳过 Question
	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5 // null + type + class

	// Answers
	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		// NAME（可能压缩）
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8 // type(2) + class(2) + ttl(4)
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

// 仅抽取 SvcParamKey == 5 (ECHConfigList/echconfig)
func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// 跳 priority(2)
	offset := 2
	// 跳 targetName
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	// SvcParams
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 {
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== WebSocket 服务端 ========================

func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"自签名组织"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

func runWebSocketServer(addr string) {
	u, err := url.Parse(addr)
	if err != nil {
		log.Fatal("无效的 WebSocket 地址:", err)
	}

	path := u.Path
	if path == "" {
		path = "/"
	}

	// 解析多个 CIDR 范围
	var allowedNets []*net.IPNet
	for _, cidr := range strings.Split(cidrs, ",") {
		_, allowedNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			log.Fatalf("无法解析 CIDR: %v", err)
		}
		allowedNets = append(allowedNets, allowedNet)
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
		Subprotocols: func() []string {
			if token == "" {
				return nil
			}
			return []string{token}
		}(),
		ReadBufferSize:  65536, // 增加读缓冲区到64KB
		WriteBufferSize: 65536, // 增加写缓冲区到64KB
	}

	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		// 验证来源IP
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("无法解析客户端地址: %v", err)
			w.Header().Set("Connection", "close")
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		clientIPAddr := net.ParseIP(clientIP)
		allowed := false
		for _, allowedNet := range allowedNets {
			if allowedNet.Contains(clientIPAddr) {
				allowed = true
				break
			}
		}
		if !allowed {
			log.Printf("拒绝访问: IP %s 不在允许的范围内 (%s)", clientIP, cidrs)
			w.Header().Set("Connection", "close")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// 验证 Subprotocol token
		if token != "" {
			clientToken := r.Header.Get("Sec-WebSocket-Protocol")
			if clientToken != token {
				log.Printf("Token验证失败，来自 %s", r.RemoteAddr)
				w.Header().Set("Connection", "close")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("WebSocket 升级失败:", err)
			return
		}

		log.Printf("新的 WebSocket 连接来自 %s", r.RemoteAddr)
		go handleWebSocket(wsConn)
	})

	// 启动服务器
	if u.Scheme == "wss" {
		server := &http.Server{
			Addr: u.Host,
		}

		if certFile != "" && keyFile != "" {
			log.Printf("WebSocket 服务端使用提供的TLS证书启动，监听 %s%s", u.Host, path)
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
		} else {
			cert, err := generateSelfSignedCert()
			if err != nil {
				log.Fatalf("生成自签名证书时出错: %v", err)
			}
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
			}
			server.TLSConfig = tlsConfig
			log.Printf("WebSocket 服务端使用自签名证书启动，监听 %s%s", u.Host, path)
			log.Fatal(server.ListenAndServeTLS("", ""))
		}
	} else {
		log.Printf("WebSocket 服务端启动，监听 %s%s", u.Host, path)
		log.Fatal(http.ListenAndServe(u.Host, nil))
	}
}

func handleWebSocket(wsConn *websocket.Conn) {
	// 创建一个 context 用于通知所有 goroutine 退出
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // 函数退出时取消所有子 goroutine

	var mu sync.Mutex
	var connMu sync.RWMutex
	conns := make(map[string]net.Conn)

	// UDP 连接管理
	udpConns := make(map[string]*net.UDPConn)
	udpTargets := make(map[string]*net.UDPAddr)

	defer func() {
		// 先取消所有 goroutine
		cancel()

		// 关闭所有 TCP 连接（这会让阻塞的 Read 立即返回错误）
		connMu.Lock()
		for id, c := range conns {
			_ = c.Close()
			log.Printf("[服务端] 清理TCP连接: %s", id)
		}
		conns = make(map[string]net.Conn)
		connMu.Unlock()

		// 关闭所有 UDP 连接
		connMu.Lock()
		for id, uc := range udpConns {
			_ = uc.Close()
			log.Printf("[服务端] 清理UDP连接: %s", id)
		}
		udpConns = make(map[string]*net.UDPConn)
		udpTargets = make(map[string]*net.UDPAddr)
		connMu.Unlock()

		// 最后关闭 WebSocket
		_ = wsConn.Close()
		log.Printf("WebSocket 连接 %s 已完全清理", wsConn.RemoteAddr())
	}()

	// 设置WebSocket保活
	wsConn.SetPingHandler(func(message string) error {
		mu.Lock()
		defer mu.Unlock()
		return wsConn.WriteMessage(websocket.PongMessage, []byte(message))
	})

	for {
		typ, msg, readErr := wsConn.ReadMessage()
		if readErr != nil {
			if !isNormalCloseError(readErr) {
				log.Printf("WebSocket 读取失败 %s: %v", wsConn.RemoteAddr(), readErr)
			}
			return // defer 会触发清理
		}

		if typ == websocket.BinaryMessage {
			// 处理 UDP 数据（带 connID）
			if len(msg) > 9 && string(msg[:9]) == "UDP_DATA:" {
				s := string(msg)
				parts := strings.SplitN(s[9:], "|", 2)
				if len(parts) == 2 {
					connID := parts[0]
					data := []byte(parts[1])

					connMu.RLock()
					udpConn, ok1 := udpConns[connID]
					targetAddr, ok2 := udpTargets[connID]
					connMu.RUnlock()
					if ok1 {
						if ok2 {
							if _, err := udpConn.WriteToUDP(data, targetAddr); err != nil {
								log.Printf("[服务端UDP:%s] 发送到目标失败: %v", connID, err)
							} else {
								log.Printf("[服务端UDP:%s] 已发送数据到 %s，大小: %d", connID, targetAddr.String(), len(data))
							}
						}
					}
				}
				continue
			}

			// 支持二进制携带文本前缀 "DATA:" 进行多路复用
			if len(msg) > 5 && string(msg[:5]) == "DATA:" {
				s := string(msg)
				parts := strings.SplitN(s[5:], "|", 2)
				if len(parts) == 2 {
					connID := parts[0]
					payload := parts[1]
					connMu.RLock()
					c, ok := conns[connID]
					connMu.RUnlock()
					if ok {
						if _, err := c.Write([]byte(payload)); err != nil && !isNormalCloseError(err) {
							log.Printf("[服务端] 写入目标失败: %v", err)
						}
					}
				}
				continue
			}
			continue
		}

		data := string(msg)

		// UDP_CONNECT: 建立 UDP 连接（带 connID）
		if strings.HasPrefix(data, "UDP_CONNECT:") {
			parts := strings.SplitN(data[12:], "|", 2)
			if len(parts) == 2 {
				connID := parts[0]
				targetAddr := parts[1]
				log.Printf("[服务端UDP:%s] 收到UDP连接请求，目标: %s", connID, targetAddr)

				udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
				if err != nil {
					log.Printf("[服务端UDP:%s] 解析目标地址失败: %v", connID, err)
					mu.Lock()
					_ = wsConn.WriteMessage(websocket.TextMessage, []byte("UDP_ERROR:"+connID+"|解析地址失败"))
					mu.Unlock()
					continue
				}

				// 为每个 UDP 连接创建独立的套接字
				udpConn, err := net.ListenUDP("udp", nil)
				if err != nil {
					log.Printf("[服务端UDP:%s] 创建UDP套接字失败: %v", connID, err)
					mu.Lock()
					_ = wsConn.WriteMessage(websocket.TextMessage, []byte("UDP_ERROR:"+connID+"|创建UDP失败"))
					mu.Unlock()
					continue
				}

				connMu.Lock()
				udpConns[connID] = udpConn
				udpTargets[connID] = udpAddr
				connMu.Unlock()

				// 启动 UDP 接收 goroutine（监听 context 取消）
				go func(cID string, uc *net.UDPConn, ctx context.Context) {
					defer func() {
						connMu.Lock()
						delete(udpConns, cID)
						delete(udpTargets, cID)
						connMu.Unlock()
						_ = uc.Close()
					}()

					buffer := make([]byte, 65535)
					for {
						select {
						case <-ctx.Done():
							log.Printf("[服务端UDP:%s] 上下文取消，退出接收循环", cID)
							return
						default:
						}

						// 设置短超时，避免永久阻塞
						_ = uc.SetReadDeadline(time.Now().Add(1 * time.Second))
						n, addr, err := uc.ReadFromUDP(buffer)
						if err != nil {
							if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
								continue // 超时继续循环，检查 ctx
							}
							if !isNormalCloseError(err) {
								log.Printf("[服务端UDP:%s] 读取失败: %v", cID, err)
							}
							return
						}

						log.Printf("[服务端UDP:%s] 收到响应来自 %s，大小: %d", cID, addr.String(), n)

						// 构建响应消息: UDP_DATA:<connID>|<host>:<port>|<data>
						host, portStr, _ := net.SplitHostPort(addr.String())
						response := []byte(fmt.Sprintf("UDP_DATA:%s|%s:%s|", cID, host, portStr))
						response = append(response, buffer[:n]...)

						mu.Lock()
						_ = wsConn.WriteMessage(websocket.BinaryMessage, response)
						mu.Unlock()
					}
				}(connID, udpConn, ctx)

				log.Printf("[服务端UDP:%s] UDP目标已设置: %s", connID, targetAddr)

				// 通知客户端连接成功
				mu.Lock()
				_ = wsConn.WriteMessage(websocket.TextMessage, []byte("UDP_CONNECTED:"+connID))
				mu.Unlock()
			}
			continue
		}

		// UDP_CLOSE: 关闭 UDP 连接
		if strings.HasPrefix(data, "UDP_CLOSE:") {
			connID := strings.TrimPrefix(data, "UDP_CLOSE:")
			connMu.Lock()
			if uc, ok := udpConns[connID]; ok {
				_ = uc.Close()
				delete(udpConns, connID)
				delete(udpTargets, connID)
				log.Printf("[服务端UDP:%s] 连接已关闭", connID)
			}
			connMu.Unlock()
			continue
		}

		// CLAIM: 认领竞选（多通道）
		if strings.HasPrefix(data, "CLAIM:") {
			parts := strings.SplitN(data[6:], "|", 2)
			if len(parts) == 2 {
				connID := parts[0]
				channelID := parts[1]
				mu.Lock()
				_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLAIM_ACK:"+connID+"|"+channelID))
				mu.Unlock()
			}
			continue
		}

		// TCP: 多路复用建连
		if strings.HasPrefix(data, "TCP:") {
			parts := strings.SplitN(data[4:], "|", 3)
			if len(parts) >= 2 {
				connID := parts[0]
				targetAddr := parts[1]
				var firstFrameData string
				if len(parts) == 3 {
					firstFrameData = parts[2]
				}

				log.Printf("[服务端] 请求TCP转发，连接ID: %s，目标: %s，首帧长度: %d", connID, targetAddr, len(firstFrameData))

				// 启动连接处理 goroutine（传入 ctx）
				go handleTCPConnection(ctx, connID, targetAddr, firstFrameData, wsConn, &mu, &connMu, conns)
			}
			continue
		} else if strings.HasPrefix(data, "DATA:") {
			parts := strings.SplitN(data[5:], "|", 2)
			if len(parts) == 2 {
				id := parts[0]
				payload := parts[1]
				connMu.RLock()
				c, ok := conns[id]
				connMu.RUnlock()
				if ok {
					if _, err := c.Write([]byte(payload)); err != nil && !isNormalCloseError(err) {
						log.Printf("[服务端] 写入目标失败: %v", err)
					}
				}
			}
			continue
		} else if strings.HasPrefix(data, "CLOSE:") {
			id := strings.TrimPrefix(data, "CLOSE:")
			connMu.Lock()
			c, ok := conns[id]
			if ok {
				_ = c.Close()
				delete(conns, id)
				log.Printf("[服务端] 客户端请求关闭连接: %s", id)
			}
			connMu.Unlock()
			continue
		}
	}
}

// ======================== 独立的 TCP 连接处理函数（监听 context） ========================
func handleTCPConnection(
	ctx context.Context,
	connID, targetAddr, firstFrameData string,
	wsConn *websocket.Conn,
	mu *sync.Mutex,
	connMu *sync.RWMutex,
	conns map[string]net.Conn,
) {
	tcpConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[服务端] 连接目标地址 %s 失败: %v", targetAddr, err)
		mu.Lock()
		_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+connID))
		mu.Unlock()
		return
	}

	// 保存连接
	connMu.Lock()
	conns[connID] = tcpConn
	connMu.Unlock()

	// 确保退出时清理
	defer func() {
		_ = tcpConn.Close()
		connMu.Lock()
		delete(conns, connID)
		connMu.Unlock()
		log.Printf("[服务端] TCP连接已清理: %s", connID)
	}()

	// 发送第一帧
	if firstFrameData != "" {
		if _, err := tcpConn.Write([]byte(firstFrameData)); err != nil {
			log.Printf("[服务端] 发送第一帧失败: %v", err)
			mu.Lock()
			_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+connID))
			mu.Unlock()
			return
		}
	}

	// 通知客户端连接成功
	mu.Lock()
	_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CONNECTED:"+connID))
	mu.Unlock()

	// 启动读取 goroutine（监听 ctx.Done()）
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32768)
		for {
			select {
			case <-ctx.Done():
				// WebSocket 已关闭，强制关闭 TCP 连接
				log.Printf("[服务端] WebSocket 已关闭，强制关闭 TCP 连接: %s", connID)
				_ = tcpConn.Close()
				return
			default:
			}

			// 设置短超时，避免永久阻塞
			_ = tcpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := tcpConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // 超时继续循环，检查 ctx
				}
				if !isNormalCloseError(err) {
					log.Printf("[服务端] 从目标读取失败: %v", err)
				}
				mu.Lock()
				_ = wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+connID))
				mu.Unlock()
				return
			}

			mu.Lock()
			writeErr := wsConn.WriteMessage(websocket.BinaryMessage, append([]byte("DATA:"+connID+"|"), buf[:n]...))
			mu.Unlock()

			if writeErr != nil {
				if !isNormalCloseError(writeErr) {
					log.Printf("[服务端] 写入 WebSocket 失败: %v", writeErr)
				}
				return
			}
		}
	}()

	// 等待读取 goroutine 结束
	<-done
}

// ======================== TCP 正向转发客户端（采用 ECH） ========================

func runTCPClient(listenForwardAddr, wsServerAddr string) {
	// 移除 tcp:// 前缀
	rulesStr := strings.TrimPrefix(listenForwardAddr, "tcp://")

	// 按逗号分割多个规则
	rules := strings.Split(rulesStr, ",")

	if len(rules) == 0 {
		log.Fatal("TCP 地址格式错误，应为 tcp://监听地址/目标地址[,监听地址/目标地址...]")
	}

	if wsServerAddr == "" {
		log.Fatal("TCP 正向转发客户端需要指定 WebSocket 服务端地址 (-f)")
	}

	u, err := url.Parse(wsServerAddr)
	if err != nil {
		log.Fatalf("[客户端] 无效的 WebSocket 服务端地址: %v", err)
	}
	if u.Scheme != "wss" {
		log.Fatalf("[客户端] 仅支持 wss://（客户端必须使用 ECH/TLS1.3）")
	}

	echPool = NewECHPool(wsServerAddr, connectionNum)
	echPool.Start()

	var wg sync.WaitGroup

	// 为每个规则启动监听器（多通道模型：启动固定数量的 WebSocket 长连接池）
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		parts := strings.Split(rule, "/")
		if len(parts) != 2 {
			log.Fatalf("规则格式错误: %s，应为 监听地址/目标地址", rule)
		}

		listenAddress := strings.TrimSpace(parts[0])
		targetAddress := strings.TrimSpace(parts[1])

		wg.Add(1)
		go func(listen, target string) {
			defer wg.Done()
			startMultiChannelTCPForwarder(listen, target, echPool)
		}(listenAddress, targetAddress)

		log.Printf("[客户端] 已添加转发规则: %s -> %s", listenAddress, targetAddress)
	}

	log.Printf("[客户端] 共启动 %d 个TCP转发监听器(多通道)", len(rules))

	// 等待所有监听器
	wg.Wait()
}

func startMultiChannelTCPForwarder(listenAddress, targetAddress string, pool *ECHPool) {
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		log.Fatalf("TCP监听失败 %s: %v", listenAddress, err)
	}
	log.Printf("[客户端] TCP正向转发(多通道)监听: %s -> %s", listenAddress, targetAddress)

	// 复用全局池

	// 接受 TCP 连接
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("[客户端] 接受TCP连接失败 %s: %v", listenAddress, err)
			}
			return
		}

		connID := uuid.New().String()
		log.Printf("[客户端] 新的TCP连接 %s，连接ID: %s", tcpConn.RemoteAddr(), connID)

		// 读取第一帧
		_ = tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 32768)
		n, _ := tcpConn.Read(buffer)
		_ = tcpConn.SetReadDeadline(time.Time{})
		first := ""
		if n > 0 {
			first = string(buffer[:n])
		}

		pool.RegisterAndClaim(connID, targetAddress, first, tcpConn)

		if !pool.WaitConnected(connID, 5*time.Second) {
			log.Printf("[客户端] 连接 %s 建立超时，关闭", connID)
			_ = tcpConn.Close()
			continue
		}

		go func(cID string, c net.Conn) {
			defer func() {
				_ = pool.SendClose(cID)
				_ = c.Close()
			}()

			buf := make([]byte, 32768)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if err := pool.SendData(cID, buf[:n]); err != nil {
					log.Printf("[客户端] 发送数据到通道失败: %v", err)
					return
				}
			}
		}(connID, tcpConn)
	}
}

// dialWebSocketWithECH 建立 WebSocket 连接（带 ECH 重试）
func dialWebSocketWithECH(wsServerAddr string, maxRetries int) (*websocket.Conn, error) {
	u, err := url.Parse(wsServerAddr)
	if err != nil {
		return nil, fmt.Errorf("解析 wsServerAddr 失败: %v", err)
	}
	serverName := u.Hostname()

	for attempt := 1; attempt <= maxRetries; attempt++ {
		echBytes, echErr := getECHList()
		if echErr != nil {
			log.Printf("[ECH] 获取 ECH 配置失败: %v", echErr)
			if attempt < maxRetries {
				log.Printf("[ECH] 尝试刷新 ECH 配置...")
				if refreshErr := refreshECH(); refreshErr != nil {
					log.Printf("[ECH] 刷新失败: %v", refreshErr)
				}
				continue
			}
			return nil, fmt.Errorf("ECH 配置不可用: %v", echErr)
		}

		tlsCfg, tlsErr := buildTLSConfigWithECH(serverName, echBytes)
		if tlsErr != nil {
			return nil, fmt.Errorf("构建 TLS(ECH) 配置失败: %v", tlsErr)
		}

		// 配置WebSocket Dialer（增加缓冲区大小）
		dialer := websocket.Dialer{
			TLSClientConfig: tlsCfg,
			Subprotocols: func() []string {
				if token == "" {
					return nil
				}
				return []string{token}
			}(),
			HandshakeTimeout: 10 * time.Second,
			ReadBufferSize:   65536, // 增加读缓冲区到64KB
			WriteBufferSize:  65536, // 增加写缓冲区到64KB
		}

		// 如果指定了IP地址，配置自定义拨号器（SNI 仍为 serverName）
		if ipAddr != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				address = net.JoinHostPort(ipAddr, port)
				return net.DialTimeout(network, address, 10*time.Second)
			}
		}

		// 连接到WebSocket服务端（必须 wss）
		wsConn, _, dialErr := dialer.Dial(wsServerAddr, nil)
		if dialErr != nil {
			// 检查是否为 ECH 相关错误
			if strings.Contains(dialErr.Error(), "ECH") || strings.Contains(dialErr.Error(), "ech") {
				log.Printf("[ECH] 连接失败（可能 ECH 公钥已轮换）: %v", dialErr)
				if attempt < maxRetries {
					log.Printf("[ECH] 尝试刷新 ECH 配置并重试 (尝试 %d/%d)...", attempt, maxRetries)
					if refreshErr := refreshECH(); refreshErr != nil {
						log.Printf("[ECH] 刷新失败: %v", refreshErr)
					}
					time.Sleep(time.Second)
					continue
				}
			}
			return nil, dialErr
		}

		return wsConn, nil
	}

	return nil, fmt.Errorf("WebSocket 连接失败，已达最大重试次数")
}

// ======================== 代理服务器（SOCKS5 + HTTP） ========================

// SOCKS5 认证方法常量
const (
	NoAuth       = uint8(0x00)
	UserPassAuth = uint8(0x02)
	NoAcceptable = uint8(0xFF)
)

// SOCKS5 请求命令
const (
	ConnectCmd      = uint8(0x01)
	BindCmd         = uint8(0x02)
	UDPAssociateCmd = uint8(0x03)
)

// SOCKS5 地址类型
const (
	IPv4Addr   = uint8(0x01)
	DomainAddr = uint8(0x03)
	IPv6Addr   = uint8(0x04)
)

// SOCKS5 响应状态码
const (
	Succeeded               = uint8(0x00)
	GeneralFailure          = uint8(0x01)
	ConnectionNotAllowed    = uint8(0x02)
	NetworkUnreachable      = uint8(0x03)
	HostUnreachable         = uint8(0x04)
	ConnectionRefused       = uint8(0x05)
	TTLExpired              = uint8(0x06)
	CommandNotSupported     = uint8(0x07)
	AddressTypeNotSupported = uint8(0x08)
)

type ProxyConfig struct {
	Username string
	Password string
	Host     string
}

// UDP关联结构（使用连接池）
type UDPAssociation struct {
	connID        string
	tcpConn       net.Conn
	udpListener   *net.UDPConn
	clientUDPAddr *net.UDPAddr
	pool          *ECHPool
	mu            sync.Mutex
	closed        bool
	done          chan bool
	connected     chan bool
	receiving     bool
}

// ======================== 多通道客户端池 ========================

type ECHPool struct {
	wsServerAddr  string
	connectionNum int

	wsConns   []*websocket.Conn
	wsMutexes []sync.Mutex

	mu               sync.RWMutex
	tcpMap           map[string]net.Conn
	udpMap           map[string]*UDPAssociation
	channelMap       map[string]int
	connInfo         map[string]struct{ targetAddr, firstFrameData string }
	claimTimes       map[string]map[int]time.Time
	connected        map[string]chan bool
	boundByChannel   map[int]string
	pendingByChannel map[int]string
}

func NewECHPool(wsServerAddr string, n int) *ECHPool {
	return &ECHPool{
		wsServerAddr:     wsServerAddr,
		connectionNum:    n,
		wsConns:          make([]*websocket.Conn, n),
		wsMutexes:        make([]sync.Mutex, n),
		tcpMap:           make(map[string]net.Conn),
		udpMap:           make(map[string]*UDPAssociation),
		channelMap:       make(map[string]int),
		connInfo:         make(map[string]struct{ targetAddr, firstFrameData string }),
		claimTimes:       make(map[string]map[int]time.Time),
		connected:        make(map[string]chan bool),
		boundByChannel:   make(map[int]string),
		pendingByChannel: make(map[int]string),
	}
}

func (p *ECHPool) Start() {
	for i := 0; i < p.connectionNum; i++ {
		go p.dialOnce(i)
	}
}

func (p *ECHPool) dialOnce(index int) {
	for {
		wsConn, err := dialWebSocketWithECH(p.wsServerAddr, 2)
		if err != nil {
			log.Printf("[客户端] 通道 %d WebSocket(ECH) 连接失败: %v，2秒后重试", index, err)
			time.Sleep(2 * time.Second)
			continue
		}
		p.wsConns[index] = wsConn
		log.Printf("[客户端] 通道 %d WebSocket(ECH) 已连接", index)
		go p.handleChannel(index, wsConn)
		return
	}
}

// RegisterAndClaim 注册一个本地TCP连接，并对所有通道发起认领
func (p *ECHPool) RegisterAndClaim(connID, target, firstFrame string, tcpConn net.Conn) {
	p.mu.Lock()
	p.tcpMap[connID] = tcpConn
	p.connInfo[connID] = struct{ targetAddr, firstFrameData string }{targetAddr: target, firstFrameData: firstFrame}
	if p.claimTimes[connID] == nil {
		p.claimTimes[connID] = make(map[int]time.Time)
	}
	if _, ok := p.connected[connID]; !ok {
		p.connected[connID] = make(chan bool, 1)
	}
	p.mu.Unlock()

	for i, ws := range p.wsConns {
		if ws == nil {
			continue
		}
		p.mu.Lock()
		p.claimTimes[connID][i] = time.Now()
		p.mu.Unlock()
		p.wsMutexes[i].Lock()
		err := ws.WriteMessage(websocket.TextMessage, []byte("CLAIM:"+connID+"|"+fmt.Sprintf("%d", i)))
		p.wsMutexes[i].Unlock()
		if err != nil {
			log.Printf("[客户端] 通道 %d 发送CLAIM失败: %v", i, err)
		}
	}
}

// RegisterUDP 注册UDP关联
func (p *ECHPool) RegisterUDP(connID string, assoc *UDPAssociation) {
	p.mu.Lock()
	p.udpMap[connID] = assoc
	if _, ok := p.connected[connID]; !ok {
		p.connected[connID] = make(chan bool, 1)
	}
	p.mu.Unlock()
}

// SendUDPConnect 发送UDP连接请求（选择第一个可用通道）
func (p *ECHPool) SendUDPConnect(connID, target string) error {
	p.mu.RLock()
	var ws *websocket.Conn
	var chID int
	for i, w := range p.wsConns {
		if w != nil {
			ws = w
			chID = i
			break
		}
	}
	p.mu.RUnlock()

	if ws == nil {
		return fmt.Errorf("没有可用的 WebSocket 连接")
	}

	// 记录通道映射
	p.mu.Lock()
	p.channelMap[connID] = chID
	p.boundByChannel[chID] = connID
	p.mu.Unlock()

	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("UDP_CONNECT:"+connID+"|"+target))
	p.wsMutexes[chID].Unlock()

	return err
}

// SendUDPData 发送UDP数据
func (p *ECHPool) SendUDPData(connID string, data []byte) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.mu.RUnlock()

	if !ok || ws == nil {
		return fmt.Errorf("未分配通道")
	}

	msg := append([]byte("UDP_DATA:"+connID+"|"), data...)
	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.BinaryMessage, msg)
	p.wsMutexes[chID].Unlock()

	return err
}

// SendUDPClose 关闭UDP连接
func (p *ECHPool) SendUDPClose(connID string) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.mu.RUnlock()

	if !ok || ws == nil {
		return nil
	}

	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("UDP_CLOSE:"+connID))
	p.wsMutexes[chID].Unlock()

	// 清理映射
	p.mu.Lock()
	delete(p.channelMap, connID)
	delete(p.boundByChannel, chID)
	delete(p.udpMap, connID)
	p.mu.Unlock()

	return err
}

func (p *ECHPool) WaitConnected(connID string, timeout time.Duration) bool {
	p.mu.RLock()
	ch := p.connected[connID]
	p.mu.RUnlock()
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (p *ECHPool) handleChannel(channelID int, wsConn *websocket.Conn) {
	wsConn.SetPingHandler(func(message string) error {
		p.wsMutexes[channelID].Lock()
		err := wsConn.WriteMessage(websocket.PongMessage, []byte(message))
		p.wsMutexes[channelID].Unlock()
		return err
	})

	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			p.wsMutexes[channelID].Lock()
			_ = wsConn.WriteMessage(websocket.PingMessage, nil)
			p.wsMutexes[channelID].Unlock()
		}
	}()

	for {
		mt, msg, err := wsConn.ReadMessage()
		if err != nil {
			log.Printf("[客户端] 通道 %d WebSocket读取失败: %v", channelID, err)
			// 重连通道
			p.redialChannel(channelID)
			return
		}

		if mt == websocket.BinaryMessage {
			// 处理 UDP 数据响应: UDP_DATA:<connID>|<host>:<port>|<data>
			if len(msg) > 9 && string(msg[:9]) == "UDP_DATA:" {
				parts := bytes.SplitN(msg[9:], []byte("|"), 3)
				if len(parts) == 3 {
					addrData := string(parts[1])
					data := parts[2]

					p.mu.RLock()
					assoc := p.udpMap[string(parts[0])]
					p.mu.RUnlock()

					if assoc != nil {
						assoc.handleUDPResponse(addrData, data)
					}
				}
				continue
			}

			// 支持二进制多路复用：DATA:<id>|<payload>
			if len(msg) > 5 && string(msg[:5]) == "DATA:" {
				s := string(msg)
				parts := strings.SplitN(s[5:], "|", 2)
				if len(parts) == 2 {
					id := parts[0]
					payload := parts[1]
					p.mu.RLock()
					c := p.tcpMap[id]
					p.mu.RUnlock()
					if c != nil {
						if _, err := c.Write([]byte(payload)); err != nil {
							log.Printf("[客户端] 写入本地TCP连接失败: %v，发送CLOSE", err)
							go p.SendClose(id)
							c.Close()
							p.mu.Lock()
							delete(p.tcpMap, id)
							p.mu.Unlock()
						}
					} else {
						go p.SendClose(id)
					}
					continue
				}
			}
			p.mu.RLock()
			connID := p.boundByChannel[channelID]
			c := p.tcpMap[connID]
			p.mu.RUnlock()
			if connID != "" && c != nil {
				if _, err := c.Write(msg); err != nil {
					log.Printf("[客户端] 通道 %d 写入本地TCP连接失败: %v，发送CLOSE", channelID, err)
					go p.SendClose(connID)
					c.Close()
					p.mu.Lock()
					delete(p.tcpMap, connID)
					p.mu.Unlock()
				}
			}
			continue
		}

		if mt == websocket.TextMessage {
			data := string(msg)

			// UDP_CONNECTED
			if strings.HasPrefix(data, "UDP_CONNECTED:") {
				connID := strings.TrimPrefix(data, "UDP_CONNECTED:")
				p.mu.RLock()
				ch := p.connected[connID]
				p.mu.RUnlock()
				if ch != nil {
					select {
					case ch <- true:
					default:
					}
				}
				continue
			}

			// UDP_ERROR
			if strings.HasPrefix(data, "UDP_ERROR:") {
				parts := strings.SplitN(data[10:], "|", 2)
				if len(parts) == 2 {
					connID := parts[0]
					errMsg := parts[1]
					log.Printf("[客户端UDP:%s] 错误: %s", connID, errMsg)
				}
				continue
			}

			if strings.HasPrefix(data, "CLAIM_ACK:") {
				parts := strings.SplitN(data[10:], "|", 2)
				if len(parts) == 2 {
					connID := parts[0]
					p.mu.Lock()
					if _, exists := p.channelMap[connID]; exists {
						p.mu.Unlock()
						continue
					}
					info, ok := p.connInfo[connID]
					if !ok {
						p.mu.Unlock()
						continue
					}
					var latency float64
					if chTimes, ok := p.claimTimes[connID]; ok {
						if t, ok := chTimes[channelID]; ok {
							latency = float64(time.Since(t).Nanoseconds()) / 1e6
							delete(chTimes, channelID)
							if len(chTimes) == 0 {
								delete(p.claimTimes, connID)
							}
						}
					}
					p.channelMap[connID] = channelID
					p.boundByChannel[channelID] = connID
					delete(p.connInfo, connID)
					p.mu.Unlock()
					log.Printf("[客户端] 通道 %d 获胜，连接 %s，延迟 %.2fms", channelID, connID, latency)
					p.wsMutexes[channelID].Lock()
					err := wsConn.WriteMessage(websocket.TextMessage, []byte("TCP:"+connID+"|"+info.targetAddr+"|"+info.firstFrameData))
					p.wsMutexes[channelID].Unlock()
					if err != nil {
						p.mu.Lock()
						if c, ok := p.tcpMap[connID]; ok {
							c.Close()
							delete(p.tcpMap, connID)
						}
						delete(p.channelMap, connID)
						delete(p.boundByChannel, channelID)
						delete(p.connInfo, connID)
						delete(p.claimTimes, connID)
						p.mu.Unlock()
						continue
					}
				}
			} else if strings.HasPrefix(data, "CONNECTED:") {
				connID := strings.TrimPrefix(data, "CONNECTED:")
				p.mu.RLock()
				ch := p.connected[connID]
				p.mu.RUnlock()
				if ch != nil {
					select {
					case ch <- true:
					default:
					}
				}
			} else if strings.HasPrefix(data, "ERROR:") {
				log.Printf("[客户端] 通道 %d 错误: %s", channelID, data)
			} else if strings.HasPrefix(data, "CLOSE:") {
				id := strings.TrimPrefix(data, "CLOSE:")
				p.mu.Lock()
				if c, ok := p.tcpMap[id]; ok {
					_ = c.Close()
					delete(p.tcpMap, id)
				}
				delete(p.channelMap, id)
				delete(p.connInfo, id)
				delete(p.claimTimes, id)
				delete(p.boundByChannel, channelID)
				p.mu.Unlock()
			}
		}
	}
}

func (p *ECHPool) redialChannel(channelID int) {
	for {
		newConn, err := dialWebSocketWithECH(p.wsServerAddr, 2)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		p.wsConns[channelID] = newConn
		log.Printf("[客户端] 通道 %d 已重连", channelID)
		go p.handleChannel(channelID, newConn)
		return
	}
}

func (p *ECHPool) SendData(connID string, b []byte) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.mu.RUnlock()
	if !ok || ws == nil {
		return fmt.Errorf("未分配通道")
	}
	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("DATA:"+connID+"|"+string(b)))
	p.wsMutexes[chID].Unlock()
	return err
}

func (p *ECHPool) SendClose(connID string) error {
	p.mu.RLock()
	chID, ok := p.channelMap[connID]
	var ws *websocket.Conn
	if ok && chID < len(p.wsConns) {
		ws = p.wsConns[chID]
	}
	p.mu.RUnlock()
	if !ok || ws == nil {
		return nil
	}
	p.wsMutexes[chID].Lock()
	err := ws.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+connID))
	p.wsMutexes[chID].Unlock()
	return err
}

func parseProxyAddr(addr string) (*ProxyConfig, error) {
	// 格式: proxy://[user:pass@]ip:port
	addr = strings.TrimPrefix(addr, "proxy://")

	config := &ProxyConfig{}

	// 检查是否有认证信息
	if strings.Contains(addr, "@") {
		parts := strings.SplitN(addr, "@", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的代理地址格式")
		}

		// 解析用户名密码
		auth := parts[0]
		if strings.Contains(auth, ":") {
			authParts := strings.SplitN(auth, ":", 2)
			config.Username = authParts[0]
			config.Password = authParts[1]
		}

		config.Host = parts[1]
	} else {
		config.Host = addr
	}

	return config, nil
}

func runProxyServer(addr, wsServerAddr string) {
	if wsServerAddr == "" {
		log.Fatal("代理服务器需要指定 WebSocket 服务端地址 (-f)")
	}

	// 验证必须使用 wss://（强制 ECH）
	u, err := url.Parse(wsServerAddr)
	if err != nil {
		log.Fatalf("解析 WebSocket 服务端地址失败: %v", err)
	}
	if u.Scheme != "wss" {
		log.Fatalf("[代理] 仅支持 wss://（客户端必须使用 ECH/TLS1.3）")
	}

	config, err := parseProxyAddr(addr)
	if err != nil {
		log.Fatalf("解析代理地址失败: %v", err)
	}

	listener, err := net.Listen("tcp", config.Host)
	if err != nil {
		log.Fatalf("代理监听失败 %s: %v", config.Host, err)
	}
	defer listener.Close()

	log.Printf("代理服务器启动（支持 SOCKS5 和 HTTP）监听: %s", config.Host)
	if config.Username != "" {
		log.Printf("代理认证已启用，用户名: %s", config.Username)
	}

	echPool = NewECHPool(wsServerAddr, connectionNum)
	echPool.Start()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}

		go handleProxyConnection(conn, config)
	}
}

func handleProxyConnection(conn net.Conn, config *ProxyConfig) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("[代理:%s] 新连接", clientAddr)

	// 设置连接超时
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 读取第一个字节判断协议类型
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Printf("[代理:%s] 读取第一个字节失败: %v", clientAddr, err)
		return
	}

	firstByte := buf[0]

	// SOCKS5: 第一个字节是 0x05
	if firstByte == 0x05 {
		log.Printf("[代理:%s] 检测到 SOCKS5 协议", clientAddr)
		handleSOCKS5Protocol(conn, config, clientAddr)
		return
	}

	// HTTP: 第一个字节是字母 (GET, POST, CONNECT, HEAD, PUT, DELETE, OPTIONS, PATCH)
	if firstByte == 'G' || firstByte == 'P' || firstByte == 'C' || firstByte == 'H' ||
		firstByte == 'D' || firstByte == 'O' {
		log.Printf("[代理:%s] 检测到 HTTP 协议", clientAddr)
		handleHTTPProtocol(conn, config, clientAddr, firstByte)
		return
	}

	log.Printf("[代理:%s] 未知协议，第一个字节: 0x%02X", clientAddr, firstByte)
}

// ======================== SOCKS5 协议处理 ========================

func handleSOCKS5Protocol(conn net.Conn, config *ProxyConfig, clientAddr string) {
	// 处理认证方法协商（需要读取剩余的认证方法）
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Printf("[SOCKS5:%s] 读取认证方法数量失败: %v", clientAddr, err)
		return
	}
	nMethods := buf[0]

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		log.Printf("[SOCKS5:%s] 读取认证方法失败: %v", clientAddr, err)
		return
	}

	// 选择认证方法
	var method uint8 = NoAuth
	if config.Username != "" && config.Password != "" {
		method = UserPassAuth
		found := false
		for _, m := range methods {
			if m == UserPassAuth {
				found = true
				break
			}
		}
		if !found {
			method = NoAcceptable
		}
	}

	// 发送选择的认证方法
	response := []byte{0x05, method}
	if _, err := conn.Write(response); err != nil {
		log.Printf("[SOCKS5:%s] 发送认证方法响应失败: %v", clientAddr, err)
		return
	}

	if method == NoAcceptable {
		log.Printf("[SOCKS5:%s] 没有可接受的认证方法", clientAddr)
		return
	}

	// 处理用户名密码认证
	if method == UserPassAuth {
		if err := handleSOCKS5UserPassAuth(conn, config); err != nil {
			log.Printf("[SOCKS5:%s] 用户名密码认证失败: %v", clientAddr, err)
			return
		}
	}

	// 处理客户端请求
	if err := handleSOCKS5Request(conn, clientAddr, config); err != nil {
		log.Printf("[SOCKS5:%s] 处理请求失败: %v", clientAddr, err)
		return
	}
}

func handleSOCKS5UserPassAuth(conn net.Conn, config *ProxyConfig) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取用户名密码认证头失败: %v", err)
	}

	version := buf[0]
	userLen := buf[1]

	if version != 1 {
		return fmt.Errorf("不支持的认证版本: %d", version)
	}

	// 读取用户名
	userBuf := make([]byte, userLen)
	if _, err := io.ReadFull(conn, userBuf); err != nil {
		return fmt.Errorf("读取用户名失败: %v", err)
	}

	// 读取密码长度
	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return fmt.Errorf("读取密码长度失败: %v", err)
	}
	passLen := passLenBuf[0]

	// 读取密码
	passBuf := make([]byte, passLen)
	if _, err := io.ReadFull(conn, passBuf); err != nil {
		return fmt.Errorf("读取密码失败: %v", err)
	}

	// 验证用户名密码
	user := string(userBuf)
	pass := string(passBuf)

	var status byte = 0x00 // 0x00表示成功
	if user != config.Username || pass != config.Password {
		status = 0x01 // 认证失败
	}

	// 发送认证结果
	response := []byte{0x01, status}
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("发送认证响应失败: %v", err)
	}

	if status != 0x00 {
		return fmt.Errorf("用户名或密码错误")
	}

	return nil
}

func handleSOCKS5Request(conn net.Conn, clientAddr string, config *ProxyConfig) error {
	// 读取请求头
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取请求头失败: %v", err)
	}

	version := buf[0]
	command := buf[1]
	atyp := buf[3]

	if version != 5 {
		return fmt.Errorf("不支持的SOCKS版本: %d", version)
	}

	// 读取目标地址
	var host string
	switch atyp {
	case IPv4Addr:
		buf = make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取IPv4地址失败: %v", err)
		}
		host = net.IP(buf).String()

	case DomainAddr:
		buf = make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取域名长度失败: %v", err)
		}
		domainLen := buf[0]
		buf = make([]byte, domainLen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取域名失败: %v", err)
		}
		host = string(buf)

	case IPv6Addr:
		buf = make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return fmt.Errorf("读取IPv6地址失败: %v", err)
		}
		host = net.IP(buf).String()

	default:
		sendSOCKS5ErrorResponse(conn, AddressTypeNotSupported)
		return fmt.Errorf("不支持的地址类型: %d", atyp)
	}

	// 读取端口
	buf = make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取端口失败: %v", err)
	}
	port := int(buf[0])<<8 | int(buf[1])

	// 目标地址
	var target string
	if atyp == IPv6Addr {
		target = fmt.Sprintf("[%s]:%d", host, port)
	} else {
		target = fmt.Sprintf("%s:%d", host, port)
	}

	log.Printf("[SOCKS5:%s] 请求访问目标: %s (命令: %d)", clientAddr, target, command)

	// 处理不同的命令
	switch command {
	case ConnectCmd:
		return handleSOCKS5Connect(conn, target, clientAddr)
	case UDPAssociateCmd:
		return handleSOCKS5UDPAssociate(conn, clientAddr, config)
	case BindCmd:
		sendSOCKS5ErrorResponse(conn, CommandNotSupported)
		return fmt.Errorf("BIND命令暂不支持")
	default:
		sendSOCKS5ErrorResponse(conn, CommandNotSupported)
		return fmt.Errorf("不支持的命令类型: %d", command)
	}
}

func sendSOCKS5ErrorResponse(conn net.Conn, status uint8) {
	response := []byte{0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	conn.Write(response)
}

func sendSOCKS5SuccessResponse(conn net.Conn) error {
	// 简单返回成功响应（绑定地址为 0.0.0.0:0）
	response := []byte{0x05, Succeeded, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := conn.Write(response)
	return err
}

func handleSOCKS5Connect(conn net.Conn, target, clientAddr string) error {
	connID := uuid.New().String()
	_ = conn.SetDeadline(time.Time{})
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buffer := make([]byte, 32768)
	n, _ := conn.Read(buffer)
	_ = conn.SetReadDeadline(time.Time{})
	first := ""
	if n > 0 {
		first = string(buffer[:n])
	}

	echPool.RegisterAndClaim(connID, target, first, conn)
	if !echPool.WaitConnected(connID, 5*time.Second) {
		sendSOCKS5ErrorResponse(conn, GeneralFailure)
		return fmt.Errorf("SOCKS5 CONNECT 超时")
	}
	if err := sendSOCKS5SuccessResponse(conn); err != nil {
		return fmt.Errorf("发送SOCKS5成功响应失败: %v", err)
	}

	defer func() {
		_ = echPool.SendClose(connID)
		_ = conn.Close()
		echPool.mu.Lock()
		delete(echPool.tcpMap, connID)
		echPool.mu.Unlock()
		log.Printf("[SOCKS5:%s] 连接断开，已发送 CLOSE 通知", clientAddr)
	}()

	buf := make([]byte, 32768)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil
		}
		if err := echPool.SendData(connID, buf[:n]); err != nil {
			log.Printf("[SOCKS5] 发送数据到通道失败: %v", err)
			return err
		}
	}
}

// ======================== SOCKS5 UDP ASSOCIATE（使用连接池） ========================

// handleSOCKS5UDPAssociate 处理UDP ASSOCIATE请求（使用ECH连接池）
func handleSOCKS5UDPAssociate(tcpConn net.Conn, clientAddr string, config *ProxyConfig) error {
	log.Printf("[SOCKS5:%s] 处理UDP ASSOCIATE请求（使用连接池）", clientAddr)

	// 获取SOCKS5服务器的监听IP（根据配置）
	host, _, err := net.SplitHostPort(config.Host)
	if err != nil {
		sendSOCKS5ErrorResponse(tcpConn, GeneralFailure)
		return fmt.Errorf("解析监听地址失败: %v", err)
	}

	// 创建UDP监听器（端口由系统自动分配，IP使用配置的监听IP）
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		sendSOCKS5ErrorResponse(tcpConn, GeneralFailure)
		return fmt.Errorf("解析UDP地址失败: %v", err)
	}

	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		sendSOCKS5ErrorResponse(tcpConn, GeneralFailure)
		return fmt.Errorf("UDP监听失败: %v", err)
	}
	defer udpListener.Close()

	// 获取实际监听的端口
	actualAddr := udpListener.LocalAddr().(*net.UDPAddr)
	log.Printf("[SOCKS5:%s] UDP中继服务器启动: %s（通过连接池）", clientAddr, actualAddr.String())

	// 发送成功响应（包含UDP中继服务器的地址和端口）
	err = sendSOCKS5UDPResponse(tcpConn, actualAddr)
	if err != nil {
		return fmt.Errorf("发送UDP响应失败: %v", err)
	}

	// 生成连接ID并创建UDP关联
	connID := uuid.New().String()
	assoc := &UDPAssociation{
		connID:      connID,
		tcpConn:     tcpConn,
		udpListener: udpListener,
		pool:        echPool,
		done:        make(chan bool, 2),
		connected:   make(chan bool, 1),
	}

	// 注册到连接池
	echPool.RegisterUDP(connID, assoc)

	log.Printf("[SOCKS5:%s] UDP关联已创建，连接ID: %s", clientAddr, connID)

	// 清除TCP连接超时（保持连接活跃）
	tcpConn.SetDeadline(time.Time{})

	// 启动UDP数据处理goroutine
	go assoc.handleUDPRelay()

	// 监听TCP控制连接（阻塞等待）
	go func() {
		buf := make([]byte, 1)
		for {
			_, err := tcpConn.Read(buf)
			if err != nil {
				log.Printf("[SOCKS5:%s] TCP控制连接断开，终止UDP关联", clientAddr)
				assoc.done <- true
				return
			}
		}
	}()

	// 等待结束信号（TCP断开或UDP出错）
	<-assoc.done

	assoc.Close()
	log.Printf("[SOCKS5:%s] UDP关联已终止，连接ID: %s", clientAddr, connID)

	return nil
}

// sendSOCKS5UDPResponse 发送UDP ASSOCIATE成功响应
func sendSOCKS5UDPResponse(conn net.Conn, udpAddr *net.UDPAddr) error {
	response := make([]byte, 0, 22)
	response = append(response, 0x05, Succeeded, 0x00)

	// 地址类型和地址
	ip := udpAddr.IP
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		response = append(response, IPv4Addr)
		response = append(response, ip4...)
	} else {
		// IPv6
		response = append(response, IPv6Addr)
		response = append(response, ip...)
	}

	// 端口
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(udpAddr.Port))
	response = append(response, port...)

	_, err := conn.Write(response)
	return err
}

// handleUDPRelay 处理UDP数据中继（使用连接池）
func (assoc *UDPAssociation) handleUDPRelay() {
	buffer := make([]byte, 65535)

	for {
		n, srcAddr, err := assoc.udpListener.ReadFromUDP(buffer)
		if err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[UDP:%s] 读取失败: %v", assoc.connID, err)
			}
			assoc.done <- true
			return
		}

		// 第一次收到UDP包时，记录客户端UDP地址
		if assoc.clientUDPAddr == nil {
			assoc.mu.Lock()
			if assoc.clientUDPAddr == nil {
				assoc.clientUDPAddr = srcAddr
				log.Printf("[UDP:%s] 客户端UDP地址: %s", assoc.connID, srcAddr.String())
			}
			assoc.mu.Unlock()
		} else {
			// 验证UDP包来自正确的客户端
			if assoc.clientUDPAddr.String() != srcAddr.String() {
				log.Printf("[UDP:%s] 忽略来自未授权地址的UDP包: %s", assoc.connID, srcAddr.String())
				continue
			}
		}

		log.Printf("[UDP:%s] 收到UDP数据包，大小: %d", assoc.connID, n)

		// 处理UDP数据包
		go assoc.handleUDPPacket(buffer[:n])
	}
}

// handleUDPPacket 处理单个UDP数据包（通过连接池）
func (assoc *UDPAssociation) handleUDPPacket(packet []byte) {
	// 解析SOCKS5 UDP请求头
	target, data, err := parseSOCKS5UDPPacket(packet)
	if err != nil {
		log.Printf("[UDP:%s] 解析UDP数据包失败: %v", assoc.connID, err)
		return
	}

	log.Printf("[UDP:%s] 目标: %s, 数据长度: %d", assoc.connID, target, len(data))

	// 通过连接池发送数据
	if err := assoc.sendUDPData(target, data); err != nil {
		log.Printf("[UDP:%s] 发送数据失败: %v", assoc.connID, err)
		return
	}
}

// sendUDPData 通过连接池发送UDP数据
func (assoc *UDPAssociation) sendUDPData(target string, data []byte) error {
	assoc.mu.Lock()
	defer assoc.mu.Unlock()

	if assoc.closed {
		return fmt.Errorf("关联已关闭")
	}

	// 只在第一次发送时建立连接
	if !assoc.receiving {
		assoc.receiving = true
		// 发送UDP_CONNECT消息（包含目标地址）
		if err := assoc.pool.SendUDPConnect(assoc.connID, target); err != nil {
			return fmt.Errorf("发送UDP_CONNECT失败: %v", err)
		}

		// 等待连接成功
		go func() {
			if !assoc.pool.WaitConnected(assoc.connID, 5*time.Second) {
				log.Printf("[UDP:%s] 连接超时", assoc.connID)
				assoc.done <- true
				return
			}
			log.Printf("[UDP:%s] 连接已建立", assoc.connID)
		}()
	}

	// 发送实际数据
	if err := assoc.pool.SendUDPData(assoc.connID, data); err != nil {
		return fmt.Errorf("发送UDP数据失败: %v", err)
	}

	return nil
}

// handleUDPResponse 处理从WebSocket返回的UDP数据
func (assoc *UDPAssociation) handleUDPResponse(addrData string, data []byte) {
	// 解析地址 "host:port"
	parts := strings.Split(addrData, ":")
	if len(parts) != 2 {
		log.Printf("[UDP:%s] 无效的地址格式: %s", assoc.connID, addrData)
		return
	}

	host := parts[0]
	port := 0
	fmt.Sscanf(parts[1], "%d", &port)

	// 构建SOCKS5 UDP响应包
	packet, err := buildSOCKS5UDPPacket(host, port, data)
	if err != nil {
		log.Printf("[UDP:%s] 构建响应包失败: %v", assoc.connID, err)
		return
	}

	// 发送回客户端
	if assoc.clientUDPAddr != nil {
		assoc.mu.Lock()
		_, err = assoc.udpListener.WriteToUDP(packet, assoc.clientUDPAddr)
		assoc.mu.Unlock()

		if err != nil {
			log.Printf("[UDP:%s] 发送UDP响应失败: %v", assoc.connID, err)
			assoc.done <- true
			return
		}

		log.Printf("[UDP:%s] 已发送UDP响应: %s:%d, 大小: %d", assoc.connID, host, port, len(data))
	}
}

func (assoc *UDPAssociation) IsClosed() bool {
	assoc.mu.Lock()
	defer assoc.mu.Unlock()
	return assoc.closed
}

func (assoc *UDPAssociation) Close() {
	assoc.mu.Lock()
	defer assoc.mu.Unlock()

	if assoc.closed {
		return
	}

	assoc.closed = true

	// 通过连接池关闭UDP连接
	if assoc.pool != nil {
		assoc.pool.SendUDPClose(assoc.connID)
	}

	if assoc.udpListener != nil {
		assoc.udpListener.Close()
	}

	log.Printf("[UDP:%s] 关联资源已清理", assoc.connID)
}

// parseSOCKS5UDPPacket 解析SOCKS5 UDP数据包
func parseSOCKS5UDPPacket(packet []byte) (string, []byte, error) {
	if len(packet) < 10 {
		return "", nil, fmt.Errorf("数据包太短")
	}

	// RSV (2字节) + FRAG (1字节)
	if packet[0] != 0 || packet[1] != 0 {
		return "", nil, fmt.Errorf("无效的RSV字段")
	}

	frag := packet[2]
	if frag != 0 {
		return "", nil, fmt.Errorf("不支持分片 (FRAG=%d)", frag)
	}

	atyp := packet[3]
	offset := 4

	var host string
	switch atyp {
	case IPv4Addr:
		if len(packet) < offset+4 {
			return "", nil, fmt.Errorf("IPv4地址不完整")
		}
		host = net.IP(packet[offset : offset+4]).String()
		offset += 4

	case DomainAddr:
		if len(packet) < offset+1 {
			return "", nil, fmt.Errorf("域名长度字段缺失")
		}
		domainLen := int(packet[offset])
		offset++
		if len(packet) < offset+domainLen {
			return "", nil, fmt.Errorf("域名数据不完整")
		}
		host = string(packet[offset : offset+domainLen])
		offset += domainLen

	case IPv6Addr:
		if len(packet) < offset+16 {
			return "", nil, fmt.Errorf("IPv6地址不完整")
		}
		host = net.IP(packet[offset : offset+16]).String()
		offset += 16

	default:
		return "", nil, fmt.Errorf("不支持的地址类型: %d", atyp)
	}

	// 端口
	if len(packet) < offset+2 {
		return "", nil, fmt.Errorf("端口字段缺失")
	}
	port := int(packet[offset])<<8 | int(packet[offset+1])
	offset += 2

	// 实际数据
	data := packet[offset:]

	var target string
	if atyp == IPv6Addr {
		target = fmt.Sprintf("[%s]:%d", host, port)
	} else {
		target = fmt.Sprintf("%s:%d", host, port)
	}

	return target, data, nil
}

// buildSOCKS5UDPPacket 构建SOCKS5 UDP响应数据包
func buildSOCKS5UDPPacket(host string, port int, data []byte) ([]byte, error) {
	packet := make([]byte, 0, 1024)

	// RSV (2字节) + FRAG (1字节)
	packet = append(packet, 0x00, 0x00, 0x00)

	// 解析地址类型
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			packet = append(packet, IPv4Addr)
			packet = append(packet, ip4...)
		} else {
			// IPv6
			packet = append(packet, IPv6Addr)
			packet = append(packet, ip...)
		}
	} else {
		// 域名
		if len(host) > 255 {
			return nil, fmt.Errorf("域名过长")
		}
		packet = append(packet, DomainAddr)
		packet = append(packet, byte(len(host)))
		packet = append(packet, []byte(host)...)
	}

	// 端口
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	packet = append(packet, portBytes...)

	// 数据
	packet = append(packet, data...)

	return packet, nil
}

// ======================== HTTP 代理协议处理 ========================

func handleHTTPProtocol(conn net.Conn, config *ProxyConfig, clientAddr string, firstByte byte) {
	// 读取完整的第一行（HTTP 请求行）
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{firstByte}), conn))

	// 读取请求行
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("[HTTP:%s] 读取请求行失败: %v", clientAddr, err)
		return
	}

	// 解析请求行: METHOD URL HTTP/VERSION
	parts := strings.SplitN(strings.TrimSpace(requestLine), " ", 3)
	if len(parts) != 3 {
		log.Printf("[HTTP:%s] 无效的请求行: %s", clientAddr, requestLine)
		return
	}

	method := parts[0]
	requestURL := parts[1]

	log.Printf("[HTTP:%s] %s %s", clientAddr, method, requestURL)

	// CONNECT 方法：建立隧道
	if method == "CONNECT" {
		handleHTTPConnect(conn, reader, config, clientAddr, requestURL)
		return
	}

	// 其他方法（GET, POST 等）：转发 HTTP 请求
	handleHTTPForward(conn, reader, config, clientAddr, method, requestURL)
}

// handleHTTPConnect 处理 HTTP CONNECT 方法（用于 HTTPS）
func handleHTTPConnect(conn net.Conn, reader *bufio.Reader, config *ProxyConfig, clientAddr, target string) {
	log.Printf("[HTTP:%s] CONNECT 到 %s", clientAddr, target)

	// 读取并验证请求头（包括认证）
	headers, err := readHTTPHeaders(reader)
	if err != nil {
		log.Printf("[HTTP:%s] 读取请求头失败: %v", clientAddr, err)
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// 验证认证（如果配置了）
	if config.Username != "" && config.Password != "" {
		authHeader := headers["Proxy-Authorization"]
		if !validateProxyAuth(authHeader, config.Username, config.Password) {
			log.Printf("[HTTP:%s] 认证失败", clientAddr)
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
			return
		}
	}

	// 使用连接池建立连接
	connID := uuid.New().String()
	_ = conn.SetDeadline(time.Time{})

	echPool.RegisterAndClaim(connID, target, "", conn)
	if !echPool.WaitConnected(connID, 5*time.Second) {
		log.Printf("[HTTP:%s] CONNECT 超时", clientAddr)
		conn.Write([]byte("HTTP/1.1 504 Gateway Timeout\r\n\r\n"))
		return
	}

	// 发送成功响应
	_, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("[HTTP:%s] 发送响应失败: %v", clientAddr, err)
		return
	}

	log.Printf("[HTTP:%s] CONNECT 隧道已建立到 %s", clientAddr, target)

	defer func() {
		_ = echPool.SendClose(connID)
		_ = conn.Close()
		echPool.mu.Lock()
		delete(echPool.tcpMap, connID)
		echPool.mu.Unlock()
		log.Printf("[HTTP:%s] CONNECT 隧道关闭", clientAddr)
	}()

	// 转发数据
	buf := make([]byte, 32768)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if err := echPool.SendData(connID, buf[:n]); err != nil {
			log.Printf("[HTTP:%s] 发送数据失败: %v", clientAddr, err)
			return
		}
	}
}

// handleHTTPForward 处理普通 HTTP 请求（GET, POST 等）
func handleHTTPForward(conn net.Conn, reader *bufio.Reader, config *ProxyConfig, clientAddr, method, requestURL string) {
	log.Printf("[HTTP:%s] 转发 %s %s", clientAddr, method, requestURL)

	// 解析目标 URL
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		log.Printf("[HTTP:%s] 解析 URL 失败: %v", clientAddr, err)
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// 读取请求头
	headers, err := readHTTPHeaders(reader)
	if err != nil {
		log.Printf("[HTTP:%s] 读取请求头失败: %v", clientAddr, err)
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}

	// 验证认证（如果配置了）
	if config.Username != "" && config.Password != "" {
		authHeader := headers["Proxy-Authorization"]
		if !validateProxyAuth(authHeader, config.Username, config.Password) {
			log.Printf("[HTTP:%s] 认证失败", clientAddr)
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
			return
		}
	}

	// 确定目标地址
	target := parsedURL.Host
	if !strings.Contains(target, ":") {
		if parsedURL.Scheme == "https" {
			target += ":443"
		} else {
			target += ":80"
		}
	}

	// 读取请求体（如果有）
	var bodyData []byte
	if contentLength, ok := headers["Content-Length"]; ok {
		var length int
		fmt.Sscanf(contentLength, "%d", &length)
		if length > 0 && length < 10*1024*1024 { // 限制最大 10MB
			bodyData = make([]byte, length)
			_, err := io.ReadFull(reader, bodyData)
			if err != nil {
				log.Printf("[HTTP:%s] 读取请求体失败: %v", clientAddr, err)
				conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
				return
			}
		}
	}

	// 构建转发请求
	var requestBuffer bytes.Buffer

	// 修改请求行：使用相对路径
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}
	requestBuffer.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))

	// 写入请求头（移除代理相关头部）
	for key, value := range headers {
		if key != "Proxy-Authorization" && key != "Proxy-Connection" {
			requestBuffer.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}

	// 确保有 Host 头
	if _, ok := headers["Host"]; !ok {
		requestBuffer.WriteString(fmt.Sprintf("Host: %s\r\n", parsedURL.Host))
	}

	requestBuffer.WriteString("\r\n")

	// 写入请求体
	if len(bodyData) > 0 {
		requestBuffer.Write(bodyData)
	}

	firstFrameData := requestBuffer.String()

	// 使用连接池建立连接
	connID := uuid.New().String()
	_ = conn.SetDeadline(time.Time{})

	echPool.RegisterAndClaim(connID, target, firstFrameData, conn)
	if !echPool.WaitConnected(connID, 5*time.Second) {
		log.Printf("[HTTP:%s] 连接超时", clientAddr)
		conn.Write([]byte("HTTP/1.1 504 Gateway Timeout\r\n\r\n"))
		return
	}

	log.Printf("[HTTP:%s] 请求已转发到 %s", clientAddr, target)

	defer func() {
		_ = echPool.SendClose(connID)
		_ = conn.Close()
		echPool.mu.Lock()
		delete(echPool.tcpMap, connID)
		echPool.mu.Unlock()
		log.Printf("[HTTP:%s] 请求处理完成", clientAddr)
	}()

	// 等待响应（响应会通过连接池返回到 conn）
	// 这里只需要保持连接，直到任一方关闭
	buf := make([]byte, 32768)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		// 客户端发送的后续数据（如果有）也转发
		if err := echPool.SendData(connID, buf[:n]); err != nil {
			log.Printf("[HTTP:%s] 发送数据失败: %v", clientAddr, err)
			return
		}
	}
}

// readHTTPHeaders 读取 HTTP 请求头
func readHTTPHeaders(reader *bufio.Reader) (map[string]string, error) {
	headers := make(map[string]string)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break // 空行表示头部结束
		}

		// 解析头部：Key: Value
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headers[key] = value
		}
	}

	return headers, nil
}

// validateProxyAuth 验证 HTTP 代理认证
func validateProxyAuth(authHeader, username, password string) bool {
	if authHeader == "" {
		return false
	}

	// 解析 Basic 认证：Basic <base64>
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}

	encoded := strings.TrimPrefix(authHeader, prefix)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}

	// 格式：username:password
	credentials := string(decoded)
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return false
	}

	return parts[0] == username && parts[1] == password
}
