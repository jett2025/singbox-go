package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func findSingboxBin() (string, error) {
	bin, err := exec.LookPath("sing-box")
	if err != nil {
		return "", fmt.Errorf("未找到 sing-box，请先安装: %w", err)
	}
	return bin, nil
}

func GenerateUUID() (string, error) {
	bin, err := findSingboxBin()
	if err != nil {
		return "", err
	}
	out, err := exec.Command(bin, "generate", "uuid").Output()
	if err != nil {
		return "", fmt.Errorf("执行 sing-box generate uuid 失败: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func GenerateRealityKeypair() (privateKey, publicKey string, err error) {
	bin, err := findSingboxBin()
	if err != nil {
		return "", "", err
	}

	out, err := exec.Command(bin, "generate", "reality-keypair").CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("执行 sing-box generate reality-keypair 失败: %w: %s", err, strings.TrimSpace(string(out)))
	}

	privateRe := regexp.MustCompile(`(?m)^PrivateKey\s*:?\s*(\S+)\s*$`)
	publicRe := regexp.MustCompile(`(?m)^PublicKey\s*:?\s*(\S+)\s*$`)

	pm := privateRe.FindStringSubmatch(string(out))
	um := publicRe.FindStringSubmatch(string(out))
	if len(pm) < 2 || len(um) < 2 {
		return "", "", fmt.Errorf("解析 reality-keypair 输出失败: %q", strings.TrimSpace(string(out)))
	}
	return pm[1], um[1], nil
}

func GenerateSS2022Password() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("生成随机数失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}

type CertPair struct {
	CertPEM         string
	KeyPEM          string
	SPKIHash        string
	CertFingerprint string
}

func GenerateSelfSignedCert() (*CertPair, error) {
	_, err := exec.LookPath("openssl")
	if err != nil {
		return nil, fmt.Errorf("未找到 openssl，请先安装: %w", err)
	}

	// 生成 ECC 私钥
	keyCmd := exec.Command("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", KeyFile)
	if out, err := keyCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("生成私钥失败: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// 生成自签证书（100 年）
	certCmd := exec.Command("openssl", "req", "-new", "-x509", "-days", "36500",
		"-key", KeyFile, "-out", CertFile,
		"-subj", "/CN=mozilla.org",
		"-addext", "subjectAltName=DNS:addons.mozilla.org")
	if out, err := certCmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("生成证书失败: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// 生成 NaiveProxy 专用证书（200 天）
	cert200Cmd := exec.Command("openssl", "req", "-new", "-x509", "-days", "200",
		"-key", KeyFile, "-out", Cert200File,
		"-subj", "/CN=mozilla.org",
		"-addext", "subjectAltName=DNS:addons.mozilla.org")
	if out, err := cert200Cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("生成 NaiveProxy 证书失败: %w: %s", err, strings.TrimSpace(string(out)))
	}

	certPEM, err := os.ReadFile(CertFile)
	if err != nil {
		return nil, fmt.Errorf("读取证书失败: %w", err)
	}
	keyPEM, err := os.ReadFile(KeyFile)
	if err != nil {
		return nil, fmt.Errorf("读取私钥失败: %w", err)
	}

	certDER, _ := pemToDER(string(certPEM))
	spkHash := sha256.Sum256(certDER)
	spkB64 := base64.StdEncoding.EncodeToString(spkHash[:])

	var fpParts []string
	for _, b := range spkHash[:] {
		fpParts = append(fpParts, fmt.Sprintf("%02X", b))
	}
	certFP := strings.Join(fpParts, ":")

	return &CertPair{
		CertPEM:         string(certPEM),
		KeyPEM:          string(keyPEM),
		SPKIHash:        spkB64,
		CertFingerprint: certFP,
	}, nil
}

func pemToDER(pemStr string) ([]byte, error) {
	re := regexp.MustCompile(`-----BEGIN CERTIFICATE-----\n([\s\S]*?)\n-----END CERTIFICATE-----`)
	m := re.FindStringSubmatch(pemStr)
	if len(m) < 2 {
		return nil, fmt.Errorf("未找到证书 PEM 块")
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(m[1], "\n", ""))
}

func GenerateNodeName() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var b [8]byte
	rand.Read(b[:])
	for i := range b {
		b[i] = chars[b[i]%byte(len(chars))]
	}
	return string(b[:])
}
