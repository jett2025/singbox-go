package main

import (
	"fmt"
	"strings"
)

type ProtocolEntry struct {
	Name string
	Port int
}

var validProtocols = []string{
	"xtls-reality", "hysteria2", "tuic", "shadowtls",
	"shadowsocks", "trojan", "vmess-ws",
	"h2-reality", "grpc-reality", "anytls", "naive",
	"http", "socks5",
}

func isValidProtocol(name string) bool {
	for _, p := range validProtocols {
		if p == name {
			return true
		}
	}
	return false
}

func ParseProtocols(raw string) ([]ProtocolEntry, error) {
	if raw == "" {
		return nil, fmt.Errorf("--protocols 不能为空")
	}

	parts := strings.Split(raw, ",")
	entries := make([]ProtocolEntry, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		name, portStr, hasPort := strings.Cut(part, "=")
		name = strings.TrimSpace(name)

		if !isValidProtocol(name) {
			return nil, fmt.Errorf("不支持的协议: %s (支持: %s)", name, strings.Join(validProtocols, ", "))
		}
		if !hasPort {
			return nil, fmt.Errorf("协议 %s 必须指定端口，格式: %s=端口号", name, name)
		}
		portStr = strings.TrimSpace(portStr)
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			return nil, fmt.Errorf("无效端口号: %s", portStr)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("端口号超出范围: %d (1-65535)", port)
		}

		entries = append(entries, ProtocolEntry{Name: name, Port: port})
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("至少需要一个协议")
	}

	return entries, nil
}
