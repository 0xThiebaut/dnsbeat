package main

import (
	"os"

	"github.com/0xThiebaut/dnsbeat/cmd"

	_ "github.com/0xThiebaut/dnsbeat/include"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
