package main

import (
	"fmt"
	"os"

	"github.com/Kevin-Umali/repyy/internal/app"
)

var version = "0.5.2-dev"

func main() {
	code, err := app.Run(os.Args[1:], os.Stdout, os.Stderr, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "repyy: %v\n", err)
	}
	os.Exit(code)
}
