/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra/doc"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:               "jwt",
	Short:             "A command line program that provides tools for JWT and JWS",
	PersistentPreRunE: configure,
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

func init() {
	rootCmd.Flags().SortFlags = false
	flags := rootCmd.PersistentFlags()
	flags.SortFlags = false

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(decodeCmd)
}

func configure(_ *cobra.Command, _ []string) error {

	return nil
}

// Execute is the entry point for command
func Execute(v, c string) {
	version, commit = v, c
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// GenDoc generates markdown docs for the command
func GenDoc(dir string) error {
	return doc.GenMarkdownTree(rootCmd, dir)
}