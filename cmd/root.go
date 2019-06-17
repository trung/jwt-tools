package cmd

import "github.com/spf13/cobra"

var RootCmd = &cobra.Command{
	Use:               "jwt",
	Short:             "A command line program that provides tools for JWT using JWS and JWE",
}

func init() {
	RootCmd.Flags().SortFlags = false
	flags := RootCmd.PersistentFlags()
	flags.SortFlags = false

	RootCmd.AddCommand(versionCmd)
	RootCmd.AddCommand(decodeCmd)
	RootCmd.AddCommand(encodeCmd)
}
