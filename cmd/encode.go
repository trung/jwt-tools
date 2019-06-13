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

// encode JWT with JWS and/or JWE
//
// example:
// jwt encode '{}' --signing-key auto://RSA?size=2048
// jwt encode '{}' --signing-key file:///file/key.pem
// jwt encode '{}' --encryption-key auto://EDSCA?xxx=xxx
// jwt encode '{}' --encryption-key https://localhost/mykey
package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/pborman/uuid"

	"github.com/trung/jwt-tools/tools"

	"github.com/spf13/cobra"
)

var (
	encodeCmd = &cobra.Command{
		Use:   "encode <stdin>|<jwt>",
		Short: "Encode JWT with JWS and/or JWE",
		Example: `- Signing with user-provided key: 
   jwt encode '{...}' --signing-key file:///var/mykey.pem
- Signing with auto-generated RSA 2048-bit key: 
   jwt encode '{...}' --signing-key auto://RS256?bits=2048
- Encrypting with user-provided key and A128GCM encryption algorithm: 
   jwt encode '{...}' --encryption-key file:///var/mykey.pem?enc=A128GCM
- Encrypting with auto-generated EDSCA key with curve P256 and A128GCM encryption algorithm: 
   jwt encode '{...}' --encryption-key auto://ECDH_ES?bits=256&enc=A128GCM`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			opts := tools.EncodingOptions{}
			if signingKeyUrl != "" {
				u, err := url.Parse(signingKeyUrl)
				if err != nil {
					return err
				}
				algo, pub, priv, err := tools.ReadSigningKey(u)
				if err != nil {
					return err
				}
				opts.SignatureAlgorithm, opts.SigningKey = algo, priv
				pubData, err := x509.MarshalPKIXPublicKey(pub)
				if err != nil {
					return err
				}
				if err := pem.Encode(os.Stdout, &pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubData,
				}); err != nil {
					return err
				}
			}
			if encryptionKeyUrl != "" {
				u, err := url.Parse(encryptionKeyUrl)
				if err != nil {
					return err
				}
				algo, enc, pub, priv, err := tools.ReadEncryptionKey(u)
				if err != nil {
					return fmt.Errorf("can't read encryption key url due to %s", err)
				}
				privData, err := x509.MarshalPKCS8PrivateKey(priv)
				if err != nil {
					return err
				}
				if err := pem.Encode(os.Stdout, &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: privData,
				}); err != nil {
					return err
				}
				opts.EncryptionKey, opts.EncryptionKeyAlgorithm, opts.EncryptionContentAlgorithm = pub, algo, enc
			}
			if keyId == "" {
				keyId = uuid.New()
			}
			opts.KeyId = keyId
			encodingOptions = opts
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println(encodingOptions.String())
			var tokenReader io.Reader
			if len(args) == 0 {
				tokenReader = os.Stdin
			} else {
				tokenReader = strings.NewReader(args[0])
			}
			encodedToken, err := tools.EncodeJWT(tokenReader, &encodingOptions)
			if err != nil {
				return err
			}
			fmt.Println("=== Encoded JWT ===")
			fmt.Println(encodedToken)
			return nil
		},
	}

	signingKeyUrl    string
	encryptionKeyUrl string
	keyId            string

	encodingOptions tools.EncodingOptions
)

func init() {
	encodeCmd.Flags().SortFlags = false
	flags := encodeCmd.PersistentFlags()
	flags.SortFlags = false

	flags.StringVar(&signingKeyUrl, "signing-key", "", "URL to private key used to sign the JWT")
	flags.StringVar(&encryptionKeyUrl, "encryption-key", "", "URL to public key used to encrypt the JWT")
	flags.StringVar(&keyId, "key-id", "", "Customize key id")
}
