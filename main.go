package main

import (
	"os"

	"github.com/spf13/cobra"
)

var protocols string
var optDomain string
var optName string

var rootCmd = &cobra.Command{
	Use:   "singbox-go",
	Short: "Sing-box 一键部署管理工具",
}

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "部署节点",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		pp, err := ParseProtocols(protocols)
		if err != nil {
			return err
		}
		return RunDeploy(pp, optDomain, optName)
	},
}

var v2raynCmd = &cobra.Command{
	Use:   "v2rayn-uri",
	Short: "显示所有节点的 V2rayN URI",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunURI()
	},
}

var clashCmd = &cobra.Command{
	Use:   "clash",
	Short: "显示所有节点的 Clash 配置",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunClash()
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "显示 sing-box 配置文件",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunConfig()
	},
}

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "显示运行日志",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunLog()
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "显示运行状态",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunStatus()
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "重启 sing-box",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunRestart()
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "停止 sing-box",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return RunStop()
	},
}

func init() {
	deployCmd.Flags().StringVarP(&protocols, "protocols", "p", "", "协议列表，格式: protocol=port (必填)")
	deployCmd.Flags().StringVarP(&optDomain, "domain", "d", "", "连接域名（默认使用公网IP）")
	deployCmd.Flags().StringVarP(&optName, "name", "n", "VM", "节点名称前缀")
	deployCmd.MarkFlagRequired("protocols")
}

func main() {
	rootCmd.AddCommand(deployCmd, v2raynCmd, clashCmd, configCmd, logCmd, statusCmd, restartCmd, stopCmd)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
