package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

func RunDeploy(entries []ProtocolEntry, domain, name string) error {
	if err := EnsureDirs(); err != nil {
		return err
	}

	uuid, err := GenerateUUID()
	if err != nil {
		return fmt.Errorf("生成 UUID 失败: %w", err)
	}
	realityPrivate, realityPublic, err := GenerateRealityKeypair()
	if err != nil {
		return fmt.Errorf("生成 Reality 密钥对失败: %w", err)
	}
	ssPassword, err := GenerateSS2022Password()
	if err != nil {
		return fmt.Errorf("生成 SS2022 密码失败: %w", err)
	}
	cert, err := GenerateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("生成自签证书失败: %w", err)
	}
	nodeName := GenerateNodeName()

	node := &NodeInfo{
		Name:             nodeName,
		UUID:             uuid,
		Password:         uuid,
		RealityPrivate:   realityPrivate,
		RealityPublic:    realityPublic,
		SSPassword:       ssPassword,
		SPKIHash:         cert.SPKIHash,
		CertFingerprint:  cert.CertFingerprint,
	}

	// 生成 inbounds
	inbounds, err := BuildInbounds(entries, node, cert, realityPrivate, realityPublic)
	if err != nil {
		return err
	}

	var flatInbounds []json.RawMessage
	for _, raw := range inbounds {
		var probe struct {
			Inbounds []json.RawMessage `json:"inbounds"`
		}
		if err := json.Unmarshal(raw, &probe); err == nil && len(probe.Inbounds) > 0 {
			flatInbounds = append(flatInbounds, probe.Inbounds...)
		} else {
			flatInbounds = append(flatInbounds, raw)
		}
	}

	cfg := BuildBaseConfig(flatInbounds)
	configData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	// 写入临时文件 → check → 覆盖
	tmpFile := ConfigFile + ".tmp"
	if err := os.WriteFile(tmpFile, configData, 0644); err != nil {
		return err
	}
	if err := checkConfigFile(tmpFile); err != nil {
		os.Remove(tmpFile)
		return err
	}
	if err := os.Rename(tmpFile, ConfigFile); err != nil {
		os.Remove(tmpFile)
		return err
	}

	// 保存 state
	state := &State{
		Name:            nodeName,
		UUID:            uuid,
		RealityPrivate:  realityPrivate,
		RealityPublic:   realityPublic,
		SSPassword:      ssPassword,
		SPKIHash:        cert.SPKIHash,
		CertFingerprint: cert.CertFingerprint,
		Domain:          domain,
		NodeName:        name,
	}
	for _, e := range entries {
		state.Nodes = append(state.Nodes, StateNode{Protocol: e.Name, Port: e.Port})
	}
	if err := SaveState(state); err != nil {
		return err
	}

	// systemd override + restart
	if err := EnsureServiceOverride(); err != nil {
		return err
	}
	if err := systemctlRestart(); err != nil {
		return err
	}

	fmt.Println("\n部署完成!")
	printURIs(state)
	return nil
}

func RunURI() error {
	state, err := LoadState()
	if err != nil {
		return err
	}
	if state == nil {
		fmt.Println("尚未部署节点，请先运行 singbox-go deploy")
		return nil
	}
	printURIs(state)
	return nil
}

func printURIs(state *State) {
	node := &NodeInfo{
		Name:             state.Name,
		UUID:             state.UUID,
		Password:         state.UUID,
		RealityPrivate:   state.RealityPrivate,
		RealityPublic:    state.RealityPublic,
		SSPassword:       state.SSPassword,
		SPKIHash:         state.SPKIHash,
		CertFingerprint:  state.CertFingerprint,
	}
	addr := state.Domain
	if addr == "" {
		addr = getServerIP()
	}
	name := state.NodeName
	if name == "" {
		name = "VM"
	}
	for _, n := range state.Nodes {
		fmt.Printf("%s\t%d\t%s\n", n.Protocol, n.Port, BuildURI(n.Protocol, node, n.Port, addr, name))
	}
}

func RunClash() error {
	state, err := LoadState()
	if err != nil {
		return err
	}
	if state == nil {
		fmt.Println("尚未部署节点，请先运行 singbox-go deploy")
		return nil
	}
	fmt.Println(BuildClashYAML(state))
	return nil
}

func RunConfig() error {
	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func RunLog() error {
	fmt.Println(journalctlLog())
	return nil
}

func RunStatus() error {
	if systemctlIsActive() {
		fmt.Println(systemctlStatus())
	} else {
		fmt.Println("sing-box 未运行")
	}
	return nil
}

func RunRestart() error {
	if _, err := os.Stat(ConfigFile); err == nil {
		if err := checkConfig(); err != nil {
			return err
		}
	}
	return systemctlRestart()
}

func RunStop() error {
	if !systemctlIsActive() {
		fmt.Println("sing-box 未运行")
		return nil
	}
	systemctlStop()
	fmt.Println("sing-box 已停止")
	return nil
}

func getServerIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func BuildURI(protocol string, node *NodeInfo, port int, addr, name string) string {
	fpNoColon := strings.ReplaceAll(node.CertFingerprint, ":", "")
	fragment := url.QueryEscape(fmt.Sprintf("%s-%d %s", name, port, protocol))

	switch protocol {
	case "xtls-reality":
		return fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=firefox&pbk=%s&type=tcp&headerType=none#%s",
			node.UUID, addr, port, tlsServer, node.RealityPublic, fragment)

	case "hysteria2":
		return fmt.Sprintf("hysteria2://%s@%s:%d?sni=%s&alpn=h3&insecure=1&allowInsecure=1&pinSHA256=%s#%s",
			node.UUID, addr, port, tlsServer, fpNoColon, fragment)

	case "tuic":
		return fmt.Sprintf("tuic://%s:%s@%s:%d?sni=%s&alpn=h3&insecure=1&allowInsecure=1&congestion_control=bbr#%s",
			node.UUID, node.UUID, addr, port, tlsServer, fragment)

	case "shadowtls":
		return ""

	case "shadowsocks":
		return fmt.Sprintf("ss://%s@%s:%d#%s",
			base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:"+node.SSPassword)),
			addr, port, fragment)

	case "trojan":
		return fmt.Sprintf("trojan://%s@%s:%d?security=tls&insecure=1&allowInsecure=1&pcs=%s&type=tcp&headerType=none#%s",
			node.UUID, addr, port, fpNoColon, fragment)

	case "vmess-ws":
		vmessObj := fmt.Sprintf(`{ "v": "2", "ps": "%s-%d vmess-ws", "add": "%s", "port": "%d", "id": "%s", "aid": "0", "scy": "none", "net": "ws", "type": "auto", "host": "%s", "path": "/%s-vmess", "tls": "", "sni": "", "alpn": "" }`,
			name, port, addr, port, node.UUID, addr, node.UUID)
		return fmt.Sprintf("vmess://%s", base64.StdEncoding.EncodeToString([]byte(vmessObj)))

	case "h2-reality":
		return fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=reality&sni=%s&fp=firefox&pbk=%s&type=http#%s",
			node.UUID, addr, port, tlsServer, node.RealityPublic, fragment)

	case "grpc-reality":
		return fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=reality&sni=%s&fp=firefox&pbk=%s&type=grpc&serviceName=grpc&mode=gun#%s",
			node.UUID, addr, port, tlsServer, node.RealityPublic, fragment)

	case "anytls":
		return fmt.Sprintf("anytls://%s@%s:%d?security=tls&sni=%s&fp=firefox&insecure=1&allowInsecure=1&type=tcp#%s",
			node.UUID, addr, port, tlsServer, fragment)

	case "naive":
		return fmt.Sprintf("naive+https://%s:%s@%s:%d#%s",
			url.QueryEscape(node.UUID), url.QueryEscape(node.UUID), addr, port, fragment)

	case "http":
		return fmt.Sprintf("http://%s:%d#%s", addr, port, fragment)

	case "socks5":
		return fmt.Sprintf("socks5://%s:%d#%s", addr, port, fragment)

	default:
		return fmt.Sprintf("%s://%s:%d#%s", protocol, addr, port, fragment)
	}
}

func BuildClashYAML(state *State) string {
	addr := state.Domain
	if addr == "" {
		addr = getServerIP()
	}
	name := state.NodeName
	if name == "" {
		name = "VM"
	}
	node := &NodeInfo{
		Name:             state.Name,
		UUID:             state.UUID,
		Password:         state.UUID,
		RealityPrivate:   state.RealityPrivate,
		RealityPublic:    state.RealityPublic,
		SSPassword:       state.SSPassword,
		SPKIHash:         state.SPKIHash,
		CertFingerprint:  state.CertFingerprint,
	}

	var lines []string
	for _, n := range state.Nodes {
		line := buildClashProxyLine(n.Protocol, n.Port, addr, node, name)
		if line != "" {
			lines = append(lines, "  - "+line)
		}
	}
	return "proxies:\n" + strings.Join(lines, "\n")
}

func buildClashProxyLine(protocol string, port int, addr string, node *NodeInfo, name string) string {
	label := fmt.Sprintf("%s-%d %s", name, port, protocol)
	smuxVision := `{ enabled: false, protocol: 'h2mux', padding: false, max-connections: '8', min-streams: '16', statistic: true, only-tcp: false }`
	smuxOn := `{ enabled: true, protocol: 'h2mux', padding: true, max-connections: '8', min-streams: '16', statistic: true, only-tcp: false }`
	brutalOff := `{ enabled: false, up: '1000 Mbps', down: '1000 Mbps' }`
	fp := node.CertFingerprint

	switch protocol {
	case "xtls-reality":
		return fmt.Sprintf(`{name: "%s", type: vless, server: %s, port: %d, uuid: %s, network: tcp, udp: true, tls: true, flow: xtls-rprx-vision, servername: %s, client-fingerprint: firefox, reality-opts: {public-key: %s, short-id: ""}, smux: %s, brutal-opts: %s }`,
			label, addr, port, node.UUID, tlsServer, node.RealityPublic, smuxVision, brutalOff)

	case "hysteria2":
		return fmt.Sprintf(`{name: "%s", type: hysteria2, server: %s, port: %d, up: "200 Mbps", down: "1000 Mbps", password: %s, sni: %s, skip-cert-verify: false, fingerprint: %s}`,
			label, addr, port, node.UUID, tlsServer, fp)

	case "tuic":
		return fmt.Sprintf(`{name: "%s", type: tuic, server: %s, port: %d, uuid: %s, password: %s, alpn: [h3], reduce-rtt: true, request-timeout: 8000, udp-relay-mode: native, congestion-controller: bbr, sni: %s, skip-cert-verify: false, fingerprint: %s}`,
			label, addr, port, node.UUID, node.UUID, tlsServer, fp)

	case "shadowtls":
		return fmt.Sprintf(`{name: "%s", type: ss, server: %s, port: %d, cipher: 2022-blake3-aes-128-gcm, password: %s, plugin: shadow-tls, client-fingerprint: firefox, plugin-opts: {host: %s, password: "%s", version: 3}, smux: %s, brutal-opts: %s }`,
			label, addr, port, node.SSPassword, tlsServer, node.UUID, smuxOn, brutalOff)

	case "shadowsocks":
		return fmt.Sprintf(`{name: "%s", type: ss, server: %s, port: %d, cipher: 2022-blake3-aes-128-gcm, password: %s, smux: %s, brutal-opts: %s }`,
			label, addr, port, node.SSPassword, smuxOn, brutalOff)

	case "trojan":
		return fmt.Sprintf(`{name: "%s", type: trojan, server: %s, port: %d, password: %s, client-fingerprint: firefox, sni: %s, skip-cert-verify: false, fingerprint: %s, smux: %s, brutal-opts: %s }`,
			label, addr, port, node.UUID, tlsServer, fp, smuxOn, brutalOff)

	case "vmess-ws":
		return fmt.Sprintf(`{name: "%s", type: vmess, server: %s, port: %d, uuid: %s, udp: true, tls: false, alterId: 0, cipher: auto, network: ws, ws-opts: { path: "/%s-vmess", headers: {Host: %s} }, smux: %s, brutal-opts: %s }`,
			label, addr, port, node.UUID, node.UUID, addr, smuxOn, brutalOff)

	case "h2-reality":
		return ""

	case "grpc-reality":
		return fmt.Sprintf(`{name: "%s", type: vless, server: %s, port: %d, uuid: %s, network: grpc, tls: true, udp: true, flow: , client-fingerprint: firefox, servername: %s, grpc-opts: {  grpc-service-name: "grpc" }, reality-opts: { public-key: %s, short-id: "" }, smux: %s, brutal-opts: %s }`,
			label, addr, port, node.UUID, tlsServer, node.RealityPublic, smuxOn, brutalOff)

	case "anytls":
		return fmt.Sprintf(`{name: "%s", type: anytls, server: %s, port: %d, password: %s, client-fingerprint: firefox, udp: true, idle-session-check-interval: 30, idle-session-timeout: 30, sni: %s, skip-cert-verify: false, fingerprint: %s }`,
			label, addr, port, node.UUID, tlsServer, fp)

	case "naive":
		return ""

	case "http":
		return fmt.Sprintf(`{name: "%s", type: http, server: %s, port: %d}`, label, addr, port)

	case "socks5":
		return fmt.Sprintf(`{name: "%s", type: socks5, server: %s, port: %d}`, label, addr, port)

	default:
		return fmt.Sprintf(`{name: "%s", server: %s, port: %d}`, label, addr, port)
	}
}

// checkConfigFile 对指定文件路径执行 sing-box check
func checkConfigFile(path string) error {
	bin, err := exec.LookPath("sing-box")
	if err != nil {
		return fmt.Errorf("未找到 sing-box: %w", err)
	}
	out, err := exec.Command(bin, "check", "-c", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("配置检查失败: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// NodeInfo 用于生成 URI 和 Clash 配置的中间结构
type NodeInfo struct {
	Name             string
	UUID             string
	Password         string
	RealityPrivate   string
	RealityPublic    string
	SSPassword       string
	SPKIHash         string
	CertFingerprint  string
}

var _ = url.QueryEscape
var _ = base64.StdEncoding
