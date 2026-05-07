package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	WorkDir           = "/etc/sing-box"
	CertDir           = WorkDir + "/cert"
	ConfigFile        = WorkDir + "/config.json"
	StateFile         = WorkDir + "/state.json"
	CertFile          = CertDir + "/cert.pem"
	Cert200File       = CertDir + "/cert_200.pem"
	KeyFile           = CertDir + "/private.key"
	ServiceOverrideDir  = "/etc/systemd/system/sing-box.service.d"
	ServiceOverrideFile = ServiceOverrideDir + "/singbox-go.conf"
)

type State struct {
	Name             string      `json:"name"`
	UUID             string      `json:"uuid"`
	RealityPrivate   string      `json:"reality_private"`
	RealityPublic    string      `json:"reality_public"`
	SSPassword       string      `json:"ss_password"`
	SPKIHash         string      `json:"spki_hash"`
	CertFingerprint  string      `json:"cert_fingerprint"`
	Domain           string      `json:"domain,omitempty"`
	NodeName         string      `json:"node_name"`
	Nodes            []StateNode `json:"nodes"`
}

type StateNode struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

func LoadState() (*State, error) {
	data, err := os.ReadFile(StateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func SaveState(s *State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(StateFile, data, 0644)
}

func EnsureDirs() error {
	for _, d := range []string{WorkDir, CertDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("创建目录 %s 失败: %w", d, err)
		}
	}
	return nil
}

func EnsureServiceOverride() error {
	if err := os.MkdirAll(ServiceOverrideDir, 0755); err != nil {
		return fmt.Errorf("创建 override 目录失败: %w", err)
	}
	content := `[Service]
ExecStart=
ExecStart=/usr/bin/sing-box -c /etc/sing-box/config.json run
`
	if err := os.WriteFile(ServiceOverrideFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("写入 service override 失败: %w", err)
	}
	out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("daemon-reload 失败: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func checkConfig() error {
	bin, err := exec.LookPath("sing-box")
	if err != nil {
		return fmt.Errorf("未找到 sing-box: %w", err)
	}
	out, err := exec.Command(bin, "check", "-c", ConfigFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("配置检查失败: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func systemctlRestart() error {
	out, err := exec.Command("systemctl", "restart", "sing-box").CombinedOutput()
	if err != nil {
		return fmt.Errorf("重启 sing-box 失败: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func systemctlStop() error {
	exec.Command("systemctl", "stop", "sing-box").Run()
	return nil
}

func systemctlIsActive() bool {
	return exec.Command("systemctl", "is-active", "--quiet", "sing-box").Run() == nil
}

func systemctlStatus() string {
	out, _ := exec.Command("systemctl", "status", "--no-pager", "sing-box").CombinedOutput()
	return string(out)
}

func journalctlLog() string {
	out, _ := exec.Command("journalctl", "-u", "sing-box", "--output", "cat", "-e", "-n", "100").CombinedOutput()
	return string(out)
}
