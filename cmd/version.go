package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version, commit string
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version of this tool",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Version:", version)
		fmt.Println(" Commit:", commit)
	},
}
