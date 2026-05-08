package main

import (
	"encoding/json"
	"fmt"
)

type SingboxConfig struct {
	Log       *LogConfig        `json:"log,omitempty"`
	NTP       *NTPConfig        `json:"ntp,omitempty"`
	DNS       *DNSConfig        `json:"dns,omitempty"`
	Inbounds  []json.RawMessage `json:"inbounds"`
	Outbounds []OutboundConfig  `json:"outbounds"`
	Route     *RouteConfig      `json:"route,omitempty"`
}

type LogConfig struct {
	Level     string `json:"level"`
	Output    string `json:"output,omitempty"`
	Timestamp bool   `json:"timestamp,omitempty"`
}

type NTPConfig struct {
	Enabled    bool   `json:"enabled"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port,omitempty"`
	Interval   string `json:"interval,omitempty"`
}

type DNSConfig struct {
	Servers []DNSServer       `json:"servers"`
	Rules   []json.RawMessage `json:"rules,omitempty"`
	Final   string            `json:"final,omitempty"`
}

type DNSServer struct {
	Tag    string `json:"tag"`
	Type   string `json:"type"`
	Server string `json:"server,omitempty"`
	Detour string `json:"detour,omitempty"`
}

type OutboundConfig struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

type RouteConfig struct {
	Rules                 []json.RawMessage `json:"rules,omitempty"`
	Final                 string            `json:"final"`
	AutoDetectInterface   bool              `json:"auto_detect_interface"`
	DefaultDomainResolver string            `json:"default_domain_resolver,omitempty"`
}

func BuildBaseConfig(inbounds []json.RawMessage) *SingboxConfig {
	return &SingboxConfig{
		Log: &LogConfig{
			Level:     "info",
			Timestamp: true,
		},
		NTP: &NTPConfig{
			Enabled:  true,
			Server:   "time.apple.com",
			Interval: "30m",
		},
		DNS: &DNSConfig{
			Servers: []DNSServer{
				{Tag: "local", Type: "local"},
				{Tag: "dns-direct", Type: "https", Server: "223.5.5.5"},
				{Tag: "dns-remote", Type: "https", Server: "8.8.8.8"},
			},
			Final: "dns-remote",
		},
		Inbounds: inbounds,
		Outbounds: []OutboundConfig{
			{Type: "direct", Tag: "direct"},
			{Type: "block", Tag: "block"},
		},
		Route: &RouteConfig{
			Final:                 "direct",
			AutoDetectInterface:   true,
			DefaultDomainResolver: "local",
		},
	}
}

func BuildInbounds(entries []ProtocolEntry, node *NodeInfo, cert *CertPair, realityPrivate, realityPublic string) ([]json.RawMessage, error) {
	var inbounds []json.RawMessage

	for _, e := range entries {
		var raw json.RawMessage
		var err error

		switch e.Name {
		case "xtls-reality":
			raw = buildXTLSReality(e.Port, node.Name, node.UUID, realityPrivate, realityPublic)
		case "hysteria2":
			raw = buildHysteria2(e.Port, node.Name, node.UUID, cert)
		case "tuic":
			raw = buildTUIC(e.Port, node.Name, node.UUID, cert)
		case "shadowtls":
			raw = buildShadowTLS(e.Port, node.Name, node.UUID, node.SSPassword)
		case "shadowsocks":
			raw = buildShadowsocks(e.Port, node.Name, node.SSPassword)
		case "trojan":
			raw = buildTrojan(e.Port, node.Name, node.UUID, cert)
		case "vmess-ws":
			raw = buildVmessWS(e.Port, node.Name, node.UUID)
		case "h2-reality":
			raw = buildH2Reality(e.Port, node.Name, node.UUID, realityPrivate, realityPublic)
		case "grpc-reality":
			raw = buildGRPCReality(e.Port, node.Name, node.UUID, realityPrivate, realityPublic)
		case "anytls":
			raw = buildAnyTLS(e.Port, node.Name, node.UUID, cert)
		case "naive":
			raw = buildNaive(e.Port, node.Name, node.UUID, cert)
		case "http":
			raw = buildHTTP(e.Port, node.Name)
		case "socks5":
			raw = buildSocks5(e.Port, node.Name)
		default:
			err = fmt.Errorf("未实现的协议: %s", e.Name)
		}

		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, raw)
	}

	return inbounds, nil
}

func mustJSON(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

const tlsServer = "addons.mozilla.org"

func buildXTLSReality(port int, name, uuid, realityPrivate, realityPublic string) json.RawMessage {
	type inbound struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
		Users      []struct {
			UUID string `json:"uuid"`
			Flow string `json:"flow"`
		} `json:"users"`
		TLS struct {
			Enabled    bool   `json:"enabled"`
			ServerName string `json:"server_name"`
			Reality    struct {
				Enabled   bool `json:"enabled"`
				Handshake struct {
					Server     string `json:"server"`
					ServerPort int    `json:"server_port"`
				} `json:"handshake"`
				PrivateKey string   `json:"private_key"`
				ShortID    []string `json:"short_id"`
			} `json:"reality"`
		} `json:"tls"`
		Multiplex struct {
			Enabled bool `json:"enabled"`
			Padding bool `json:"padding"`
		} `json:"multiplex"`
	}

	var v inbound
	v.Type = "vless"
	v.Tag = name + " xtls-reality"
	v.Listen = "::"
	v.ListenPort = port
	v.Users = []struct {
		UUID string `json:"uuid"`
		Flow string `json:"flow"`
	}{{UUID: uuid, Flow: "xtls-rprx-vision"}}
	v.TLS.Enabled = true
	v.TLS.ServerName = tlsServer
	v.TLS.Reality.Enabled = true
	v.TLS.Reality.Handshake.Server = tlsServer
	v.TLS.Reality.Handshake.ServerPort = 443
	v.TLS.Reality.PrivateKey = realityPrivate
	v.TLS.Reality.ShortID = []string{""}
	v.Multiplex.Enabled = false
	v.Multiplex.Padding = false

	return mustJSON(v)
}

func buildHysteria2(port int, name, uuid string, cert *CertPair) json.RawMessage {
	var v struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
		Users      []struct {
			Password string `json:"password"`
		} `json:"users"`
		IgnoreClientBandwidth bool `json:"ignore_client_bandwidth"`
		TLS                   struct {
			Enabled    bool     `json:"enabled"`
			ALPN       []string `json:"alpn"`
			MinVersion string   `json:"min_version"`
			MaxVersion string   `json:"max_version"`
			CertPath   string   `json:"certificate_path"`
			KeyPath    string   `json:"key_path"`
		} `json:"tls"`
	}
	v.Type = "hysteria2"
	v.Tag = name + " hysteria2"
	v.Listen = "::"
	v.ListenPort = port
	v.Users = []struct {
		Password string `json:"password"`
	}{{Password: uuid}}
	v.IgnoreClientBandwidth = false
	v.TLS.Enabled = true
	v.TLS.ALPN = []string{"h3"}
	v.TLS.MinVersion = "1.3"
	v.TLS.MaxVersion = "1.3"
	v.TLS.CertPath = CertFile
	v.TLS.KeyPath = KeyFile

	return mustJSON(v)
}

func buildTUIC(port int, name, uuid string, cert *CertPair) json.RawMessage {
	var v struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
		Users      []struct {
			UUID     string `json:"uuid"`
			Password string `json:"password"`
		} `json:"users"`
		CongestionControl string `json:"congestion_control"`
		ZeroRTTHandshake  bool   `json:"zero_rtt_handshake"`
		TLS               struct {
			Enabled  bool     `json:"enabled"`
			ALPN     []string `json:"alpn"`
			CertPath string   `json:"certificate_path"`
			KeyPath  string   `json:"key_path"`
		} `json:"tls"`
	}
	v.Type = "tuic"
	v.Tag = name + " tuic"
	v.Listen = "::"
	v.ListenPort = port
	v.Users = []struct {
		UUID     string `json:"uuid"`
		Password string `json:"password"`
	}{{UUID: uuid, Password: uuid}}
	v.CongestionControl = "bbr"
	v.ZeroRTTHandshake = false
	v.TLS.Enabled = true
	v.TLS.ALPN = []string{"h3"}
	v.TLS.CertPath = CertFile
	v.TLS.KeyPath = KeyFile

	return mustJSON(v)
}

func buildShadowTLS(port int, name, uuid, ssPassword string) json.RawMessage {
	type shadowtlsInbound struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
		Detour     string `json:"detour"`
		Version    int    `json:"version"`
		Users      []struct {
			Password string `json:"password"`
		} `json:"users"`
		Handshake struct {
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
		} `json:"handshake"`
		StrictMode bool `json:"strict_mode"`
	}

	type ssInbound struct {
		Type      string `json:"type"`
		Tag       string `json:"tag"`
		Listen    string `json:"listen"`
		Network   string `json:"network"`
		Method    string `json:"method"`
		Password  string `json:"password"`
		Multiplex struct {
			Enabled bool `json:"enabled"`
			Padding bool `json:"padding"`
		} `json:"multiplex"`
	}

	var st shadowtlsInbound
	st.Type = "shadowtls"
	st.Tag = name + " shadowtls"
	st.Listen = "::"
	st.ListenPort = port
	st.Detour = "shadowtls-in"
	st.Version = 3
	st.Users = []struct {
		Password string `json:"password"`
	}{{Password: uuid}}
	st.Handshake.Server = tlsServer
	st.Handshake.ServerPort = 443
	st.StrictMode = true

	var ss ssInbound
	ss.Type = "shadowsocks"
	ss.Tag = "shadowtls-in"
	ss.Listen = "127.0.0.1"
	ss.Network = "tcp"
	ss.Method = "2022-blake3-aes-128-gcm"
	ss.Password = ssPassword
	ss.Multiplex.Enabled = true
	ss.Multiplex.Padding = true

	result := struct {
		Inbounds []json.RawMessage `json:"inbounds"`
	}{
		Inbounds: []json.RawMessage{mustJSON(st), mustJSON(ss)},
	}
	return mustJSON(result)
}

func buildShadowsocks(port int, name, ssPassword string) json.RawMessage {
	var v struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
		Method     string `json:"method"`
		Password   string `json:"password"`
		Multiplex  struct {
			Enabled bool `json:"enabled"`
			Padding bool `json:"padding"`
		} `json:"multiplex"`
	}
	v.Type = "shadowsocks"
	v.Tag = name + " shadowsocks"
	v.Listen = "::"
	v.ListenPort = port
	v.Method = "2022-blake3-aes-128-gcm"
	v.Password = ssPassword
	v.Multiplex.Enabled = true
	v.Multiplex.Padding = true

	return mustJSON(v)
}

func buildTrojan(port int, name, uuid string, cert *CertPair) json.RawMessage {
	var v struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
		Users      []struct {
			Password string `json:"password"`
		} `json:"users"`
		TLS struct {
			Enabled  bool   `json:"enabled"`
			CertPath string `json:"certificate_path"`
			KeyPath  string `json:"key_path"`
		} `json:"tls"`
		Multiplex struct {
			Enabled bool `json:"enabled"`
			Padding bool `json:"padding"`
		} `json:"multiplex"`
	}
	v.Type = "trojan"
	v.Tag = name + " trojan"
	v.Listen = "::"
	v.ListenPort = port
	v.Users = []struct {
		Password string `json:"password"`
	}{{Password: uuid}}
	v.TLS.Enabled = true
	v.TLS.CertPath = CertFile
	v.TLS.KeyPath = KeyFile
	v.Multiplex.Enabled = true
	v.Multiplex.Padding = true

	return mustJSON(v)
}

func buildVmessWS(port int, name, uuid string) json.RawMessage {
	var v struct {
		Type          string `json:"type"`
		Tag           string `json:"tag"`
		Listen        string `json:"listen"`
		ListenPort    int    `json:"listen_port"`
		TCPFastOpen   bool   `json:"tcp_fast_open"`
		ProxyProtocol bool   `json:"proxy_protocol"`
		Users         []struct {
			UUID    string `json:"uuid"`
			AlterID int    `json:"alterId"`
		} `json:"users"`
		Transport struct {
			Type                string `json:"type"`
			Path                string `json:"path"`
			MaxEarlyData        int    `json:"max_early_data"`
			EarlyDataHeaderName string `json:"early_data_header_name"`
		} `json:"transport"`
		Multiplex struct {
			Enabled bool `json:"enabled"`
			Padding bool `json:"padding"`
		} `json:"multiplex"`
	}
	v.Type = "vmess"
	v.Tag = name + " vmess-ws"
	v.Listen = "::"
	v.ListenPort = port
	v.Users = []struct {
		UUID    string `json:"uuid"`
		AlterID int    `json:"alterId"`
	}{{UUID: uuid, AlterID: 0}}
	v.Transport.Type = "ws"
	v.Transport.Path = "/" + uuid + "-vmess"
	v.Transport.MaxEarlyData = 2560
	v.Transport.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
	v.Multiplex.Enabled = true
	v.Multiplex.Padding = true

	return mustJSON(v)
}

func buildH2Reality(port int, name, uuid, realityPrivate, realityPublic string) json.RawMessage {
	var v struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
		Users      []struct {
			UUID string `json:"uuid"`
		} `json:"users"`
		TLS struct {
			Enabled    bool   `json:"enabled"`
			ServerName string `json:"server_name"`
			Reality    struct {
				Enabled   bool `json:"enabled"`
				Handshake struct {
					Server     string `json:"server"`
					ServerPort int    `json:"server_port"`
				} `json:"handshake"`
				PrivateKey string   `json:"private_key"`
				ShortID    []string `json:"short_id"`
			} `json:"reality"`
		} `json:"tls"`
		Transport struct {
			Type string `json:"type"`
		} `json:"transport"`
		Multiplex struct {
			Enabled bool `json:"enabled"`
			Padding bool `json:"padding"`
		} `json:"multiplex"`
	}
	v.Type = "vless"
	v.Tag = name + " h2-reality"
	v.Listen = "::"
	v.ListenPort = port
	v.Users = []struct {
		UUID string `json:"uuid"`
	}{{UUID: uuid}}
	v.TLS.Enabled = true
	v.TLS.ServerName = tlsServer
	v.TLS.Reality.Enabled = true
	v.TLS.Reality.Handshake.Server = tlsServer
	v.TLS.Reality.Handshake.ServerPort = 443
	v.TLS.Reality.PrivateKey = realityPrivate
	v.TLS.Reality.ShortID = []string{""}
	v.Transport.Type = "http"
	v.Multiplex.Enabled = true
	v.Multiplex.Padding = true

	return mustJSON(v)
}

func buildGRPCReality(port int, name, uuid, realityPrivate, realityPublic string) json.RawMessage {
	var v struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
		Users      []struct {
			UUID string `json:"uuid"`
		} `json:"users"`
		TLS struct {
			Enabled    bool   `json:"enabled"`
			ServerName string `json:"server_name"`
			Reality    struct {
				Enabled   bool `json:"enabled"`
				Handshake struct {
					Server     string `json:"server"`
					ServerPort int    `json:"server_port"`
				} `json:"handshake"`
				PrivateKey string   `json:"private_key"`
				ShortID    []string `json:"short_id"`
			} `json:"reality"`
		} `json:"tls"`
		Transport struct {
			Type        string `json:"type"`
			ServiceName string `json:"service_name"`
		} `json:"transport"`
		Multiplex struct {
			Enabled bool `json:"enabled"`
			Padding bool `json:"padding"`
		} `json:"multiplex"`
	}
	v.Type = "vless"
	v.Tag = name + " grpc-reality"
	v.Listen = "::"
	v.ListenPort = port
	v.Users = []struct {
		UUID string `json:"uuid"`
	}{{UUID: uuid}}
	v.TLS.Enabled = true
	v.TLS.ServerName = tlsServer
	v.TLS.Reality.Enabled = true
	v.TLS.Reality.Handshake.Server = tlsServer
	v.TLS.Reality.Handshake.ServerPort = 443
	v.TLS.Reality.PrivateKey = realityPrivate
	v.TLS.Reality.ShortID = []string{""}
	v.Transport.Type = "grpc"
	v.Transport.ServiceName = "grpc"
	v.Multiplex.Enabled = true
	v.Multiplex.Padding = true

	return mustJSON(v)
}

func buildAnyTLS(port int, name, uuid string, cert *CertPair) json.RawMessage {
	var v struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
		Users      []struct {
			Password string `json:"password"`
		} `json:"users"`
		PaddingScheme []interface{} `json:"padding_scheme"`
		TLS           struct {
			Enabled  bool   `json:"enabled"`
			CertPath string `json:"certificate_path"`
			KeyPath  string `json:"key_path"`
		} `json:"tls"`
	}
	v.Type = "anytls"
	v.Tag = name + " anytls"
	v.Listen = "::"
	v.ListenPort = port
	v.Users = []struct {
		Password string `json:"password"`
	}{{Password: uuid}}
	v.PaddingScheme = []interface{}{}
	v.TLS.Enabled = true
	v.TLS.CertPath = CertFile
	v.TLS.KeyPath = KeyFile

	return mustJSON(v)
}

func buildNaive(port int, name, uuid string, cert *CertPair) json.RawMessage {
	var v struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
		Users      []struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"users"`
		TLS struct {
			Enabled  bool   `json:"enabled"`
			CertPath string `json:"certificate_path"`
			KeyPath  string `json:"key_path"`
		} `json:"tls"`
	}
	v.Type = "naive"
	v.Tag = name + " naive"
	v.Listen = "::"
	v.ListenPort = port
	v.Users = []struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{{Username: uuid, Password: uuid}}
	v.TLS.Enabled = true
	v.TLS.CertPath = Cert200File
	v.TLS.KeyPath = KeyFile

	return mustJSON(v)
}

func buildHTTP(port int, name string) json.RawMessage {
	var v struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
	}
	v.Type = "http"
	v.Tag = name + " http"
	v.Listen = "::"
	v.ListenPort = port
	return mustJSON(v)
}

func buildSocks5(port int, name string) json.RawMessage {
	var v struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
	}
	v.Type = "socks"
	v.Tag = name + " socks5"
	v.Listen = "::"
	v.ListenPort = port
	return mustJSON(v)
}
