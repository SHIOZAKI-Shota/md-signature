package main

import (
	"os"

	"github.com/SHIOZAKI-Shota/md-signature/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
