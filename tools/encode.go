package tools

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/square/go-jose.v2/jwt"

	"gopkg.in/square/go-jose.v2"
)

type EncodingOptions struct {
	SignatureAlgorithm jose.SignatureAlgorithm
	SigningKey         crypto.PrivateKey

	EncryptionKeyAlgorithm     jose.KeyAlgorithm
	EncryptionContentAlgorithm jose.ContentEncryption
	EncryptionKey              crypto.PublicKey

	KeyId string
}

func (eopts *EncodingOptions) String() string {
	s := new(strings.Builder)
	s.WriteString("KeyID: ")
	s.WriteString(eopts.KeyId)
	s.WriteString("\nSigningAlgorithm          : ")
	s.WriteString(string(eopts.SignatureAlgorithm))
	s.WriteString("\nEncryptionKeyAlgorithm    : ")
	s.WriteString(string(eopts.EncryptionKeyAlgorithm))
	s.WriteString("\nContentEncryptionAlgorithm: ")
	s.WriteString(string(eopts.EncryptionContentAlgorithm))
	return s.String()
}

func EncodeJWT(jsonReader io.Reader, opts *EncodingOptions) (string, error) {
	var token map[string]interface{}
	if err := json.NewDecoder(jsonReader).Decode(&token); err != nil {
		return "", err
	}
	var signer jose.Signer
	var encrypter jose.Encrypter
	if opts.SigningKey != nil {
		key := jose.SigningKey{
			Algorithm: opts.SignatureAlgorithm,
			Key: &jose.JSONWebKey{
				KeyID: opts.KeyId,
				Key:   opts.SigningKey,
			},
		}
		sig, err := jose.NewSigner(key, (&jose.SignerOptions{EmbedJWK: false}).WithType("JWT").WithContentType("JWT"))
		if err != nil {
			return "", err
		}
		signer = sig
	}
	if opts.EncryptionKey != nil {
		enc, err := jose.NewEncrypter(opts.EncryptionContentAlgorithm, jose.Recipient{
			Algorithm: opts.EncryptionKeyAlgorithm,
			Key:       opts.EncryptionKey,
		}, &jose.EncrypterOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				jose.HeaderContentType: jose.ContentType("JWT"),
			},
		})
		if err != nil {
			return "", err
		}
		encrypter = enc
	}
	if signer != nil && encrypter == nil {
		return jwt.Signed(signer).Claims(token).CompactSerialize()
	}
	if signer != nil && encrypter != nil {
		return jwt.SignedAndEncrypted(signer, encrypter).Claims(token).CompactSerialize()
	}
	if signer == nil && encrypter != nil {
		return jwt.Encrypted(encrypter).Claims(token).CompactSerialize()
	}
	return "", fmt.Errorf("required signer and/or encrypter")
}
