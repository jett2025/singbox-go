# singbox-go

Go 版 sing-box 一键部署管理工具。

## 前置要求

- Linux VPS（Debian 12 推荐）
- sing-box 已安装（`curl -fsSL https://sing-box.app/install.sh | sudo sh` 或从 [官方](https://sing-box.sagernet.org) 下载）

## 安装

### 方式一：直接下载二进制（推荐）

```bash
# 从 GitHub Releases 下载
sudo curl -L -o /usr/local/bin/singbox-go https://github.com/jett2025/singbox-go/releases/latest/download/singbox-go && sudo chmod +x /usr/local/bin/singbox-go
```

### 方式二：从源码编译

```bash
# 安装 Go
wget https://go.dev/dl/go1.23.9.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.9.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# 拉取编译
git clone https://github.com/jett2025/singbox-go.git
cd singbox-go
go build -o singbox-go .
sudo mv singbox-go /usr/local/bin/
```

## 使用

```bash
# 部署节点（必须指定协议=端口，可选指定域名和名称前缀）
sudo singbox-go deploy -p xtls-reality=9001,hysteria2=9002,tuic=9003,shadowtls=9004,shadowsocks=9005,trojan=9006,vmess-ws=9007,h2-reality=9008,grpc-reality=9009,anytls=9010,naive=9011 --domain dmit.us.rootde.com --name dmit

# 使用域名部署
sudo singbox-go deploy -p xtls-reality=9001 --domain example.com

# 自定义节点名称前缀（默认 VM）
sudo singbox-go deploy -p xtls-reality=9001 --name HK

# 显示所有节点的 V2RayN URI
sudo singbox-go v2rayn-uri

# 显示所有节点的 Clash 配置
sudo singbox-go clash

# 显示 sing-box 配置文件
sudo singbox-go config

# 显示运行日志
sudo singbox-go log

# 显示运行状态
sudo singbox-go status

# 重启 sing-box
sudo singbox-go restart

# 停止 sing-box
sudo singbox-go stop
```

## 支持的协议

| 标识 | 协议 |
|------|------|
| `xtls-reality` | VLESS + Reality |
| `hysteria2` | Hysteria2 |
| `tuic` | TUIC V5 |
| `shadowtls` | ShadowTLS |
| `shadowsocks` | Shadowsocks |
| `trojan` | Trojan |
| `vmess-ws` | VMess + WebSocket |
| `h2-reality` | H2 + Reality |
| `grpc-reality` | gRPC + Reality |
| `anytls` | AnyTLS |
| `naive` | NaiveProxy |

## 输出文件

| 文件 | 说明 |
|------|------|
| `/etc/sing-box/config.json` | sing-box 主配置 |
| `/etc/sing-box/cert/` | 自签证书目录 |
| `/etc/sing-box/state.json` | 部署状态 |

## License

GPL v3
