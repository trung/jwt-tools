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
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trung/jwt-tools/display"
	"github.com/trung/jwt-tools/tools"
)

var (
	decodeCmd = &cobra.Command{
		Use:   "decode <stdin>|<token string>",
		Short: "Decode and verify JWT using JWS and/or JWE",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			verificationOptions = new(tools.VerificationOptions)
			if jwksUrl != "" {
				u, err := url.Parse(jwksUrl)
				if err != nil {
					return err
				}
				verificationOptions.JkwsFunc = tools.JkwsHandlerFunc(u)
			}

			if decryptionKeyUrl != "" {
				u, err := url.Parse(decryptionKeyUrl)
				if err != nil {
					return err
				}
				verificationOptions.DecryptionKeyFunc = tools.DecryptionKeyHandlerFunc(u)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var tokenReader io.Reader
			if len(args) == 0 {
				tokenReader = os.Stdin
			} else {
				tokenReader = strings.NewReader(args[0])
			}
			headers, token, err := tools.DecodeJWT(tokenReader, isJWS, isJWE, verificationOptions)
			if err != nil {
				return err
			}
			fmt.Println("=== Headers ===")
			if err := display.PrintJSON(headers); err != nil {
				return err
			}
			fmt.Println("=== Payload ===")
			if err := display.PrintJSON(token); err != nil {
				return err
			}
			return nil
		},
	}
	isJWS            bool
	isJWE            bool
	jwksUrl          string
	decryptionKeyUrl string

	verificationOptions *tools.VerificationOptions
)

func init() {
	decodeCmd.Flags().SortFlags = false
	flags := decodeCmd.PersistentFlags()
	flags.SortFlags = false

	flags.BoolVar(&isJWS, "jws", false, "JWT with JSON Web Signature")
	flags.StringVar(&jwksUrl, "jwks-url", "", "URL to obtain JSON Web Keysets to validate JWS if --jws is provided")
	flags.BoolVar(&isJWE, "jwe", false, "JWT with JSON Web Encryption")
	flags.StringVar(&decryptionKeyUrl, "decryption-key-url", "", "URL to obtain decryption key if --jws and --jwe are provided")
}
