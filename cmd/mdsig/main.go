package main

import (
	"os"

	"mdsig.dev/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
