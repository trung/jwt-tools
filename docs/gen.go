package main

import (
	"fmt"
	"os"

	"github.com/trung/jwt-tools/cmd"
)

func main() {
	if err := cmd.GenDoc("./docs"); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
