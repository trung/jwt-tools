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
		Short: "Decode JWT",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			verificationOptions = new(tools.VerificationOptions)
			if jwksEndpoint != "" {
				u, err := url.Parse(jwksEndpoint)
				if err != nil {
					return err
				}
				verificationOptions.JkwsFunc = tools.JkwsHandlerFunc(u)
			}

			if decryptionKeyEndpoint != "" {
				u, err := url.Parse(decryptionKeyEndpoint)
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
	isJWS                 bool
	isJWE                 bool
	jwksEndpoint          string
	decryptionKeyEndpoint string

	verificationOptions *tools.VerificationOptions
)

func init() {
	decodeCmd.Flags().SortFlags = false
	flags := decodeCmd.PersistentFlags()
	flags.SortFlags = false

	flags.BoolVar(&isJWS, "jws", false, "JWT with JSON Web Signature")
	flags.StringVar(&jwksEndpoint, "keys-url", "", "URL to obtain JSON Web Keysets if --jws is provided")
	flags.BoolVar(&isJWE, "jwe", false, "JWT with JSON Web Encryption")
	flags.StringVar(&decryptionKeyEndpoint, "decryption-key-url", "", "URL to obtain decryption key if --jws and --jwe are provided")
}
