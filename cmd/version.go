package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version  = "0.2"
	codename = "XrayR"
	buildBy  = "Vergelab"
	intro    = "A Xray backend that supports many panels"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print current version of XrayR",
		Run: func(cmd *cobra.Command, args []string) {
			showVersion()
		},
	})
}

func showVersion() {
	fmt.Printf("%s %s (%s)\n%s\n", codename, version, buildBy, intro)
}
