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

package tools

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/ed25519"

	"gopkg.in/square/go-jose.v2"
)

func JkwsHandlerFunc(u *url.URL) JSONWebKeySetProviderFunc {
	if u != nil {
		return func() (*jose.JSONWebKeySet, error) {
			data, err := readFromURL(u)
			if err != nil {
				return nil, fmt.Errorf("unable to obtain JSON Web Keysets from %s due to %s", u, err)
			}
			var ks jose.JSONWebKeySet
			if err := json.NewDecoder(bytes.NewReader(data)).Decode(&ks); err != nil {
				return nil, fmt.Errorf("unable to decode JSON Web Keysets from [%s] due to %s", string(data), err)
			}
			return &ks, nil
		}
	}
	return nil
}

func DecryptionKeyHandlerFunc(u *url.URL) DecryptionKeyProviderFunc {
	if u != nil {
		return func() (interface{}, error) {
			data, err := readFromURL(u)
			if err != nil {
				return nil, fmt.Errorf("unable to obtain decryption key from %s due to %s", u, err)
			}
			return loadPrivateKey(data)
		}
	}
	return nil
}

func readFromURL(u *url.URL) ([]byte, error) {
	httpGet := func(c *http.Client) ([]byte, error) {
		resp, err := c.Get(u.String())
		if err != nil {
			return nil, err
		}
		defer func() {
			_ = resp.Body.Close()
		}()
		return ioutil.ReadAll(resp.Body)
	}
	switch u.Scheme {
	case "http":
		return httpGet(&http.Client{})
	case "https":
		return httpGet(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		})
	case "file":
		return ioutil.ReadFile(filepath.Join(u.Host, u.Path))
	}
	return nil, fmt.Errorf("unsupported url scheme [%s]", u)
}

// loadPrivateKey loads a private key from PEM/DER/JWK-encoded data.
func loadPrivateKey(data []byte) (interface{}, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS1PrivateKey(input)
	if err0 == nil {
		return priv, nil
	}

	priv, err1 := x509.ParsePKCS8PrivateKey(input)
	if err1 == nil {
		return priv, nil
	}

	priv, err2 := x509.ParseECPrivateKey(input)
	if err2 == nil {
		return priv, nil
	}

	jwk, err3 := loadJSONWebKey(input, false)
	if err3 == nil {
		return jwk, nil
	}

	return nil, errors.New("parse error, invalid private key")
}

func loadJSONWebKey(json []byte, pub bool) (*jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(json)
	if err != nil {
		return nil, err
	}
	if !jwk.Valid() {
		return nil, errors.New("invalid JWK key")
	}
	if jwk.IsPublic() != pub {
		return nil, errors.New("priv/pub JWK key mismatch")
	}
	return &jwk, nil
}

func ReadSigningKey(u *url.URL) (jose.SignatureAlgorithm, crypto.PublicKey, crypto.PrivateKey, error) {
	switch u.Scheme {
	case "auto":
		signatureAlgorithm := jose.SignatureAlgorithm(u.Host)
		bits, _ := strconv.Atoi(u.Query().Get("bits"))
		pub, priv, err := keygenSig(signatureAlgorithm, bits)
		return signatureAlgorithm, pub, priv, err
	case "file":
	case "http":
	case "https":
	}
	return "", nil, nil, fmt.Errorf("unsupported signing key url [%s]", u)
}

func ReadEncryptionKey(u *url.URL) (jose.KeyAlgorithm, jose.ContentEncryption, crypto.PublicKey, crypto.PrivateKey, error) {
	switch u.Scheme {
	case "auto":
		algo := jose.KeyAlgorithm(u.Host)
		bits, _ := strconv.Atoi(u.Query().Get("bits"))
		enc := jose.A128GCM
		encValue := u.Query().Get("enc")
		if encValue != "" {
			enc = jose.ContentEncryption(encValue)
		}
		pub, priv, err := keygenEnc(algo, bits)
		return algo, enc, pub, priv, err
	case "file":
	case "http":
	case "https":
	}
	return "", "", nil, nil, fmt.Errorf("unsupported encryption key url [%s]", u)
}

// KeygenSig generates keypair for corresponding SignatureAlgorithm.
func keygenSig(alg jose.SignatureAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
		keylen := map[jose.SignatureAlgorithm]int{
			jose.ES256: 256,
			jose.ES384: 384,
			jose.ES512: 521, // sic!
			jose.EdDSA: 256,
		}
		if bits != 0 && bits != keylen[alg] {
			return nil, nil, errors.New("this `alg` does not support arbitrary key length")
		}
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("too short key for RSA `alg`, 2048+ is required")
		}
	}
	switch alg {
	case jose.ES256:
		// The cryptographic operations are implemented using constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, nil
	case jose.ES384:
		// NB: The cryptographic operations do not use constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, nil
	case jose.ES512:
		// NB: The cryptographic operations do not use constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, nil
	case jose.EdDSA:
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		return pub, key, err
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, nil
	default:
		return nil, nil, fmt.Errorf("unknown `alg`:%s for `use` = `sig`", alg)
	}
}

// KeygenEnc generates keypair for corresponding KeyAlgorithm.
func keygenEnc(alg jose.KeyAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("too short key for RSA `alg`, 2048+ is required")
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, nil
	case jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW:
		var crv elliptic.Curve
		switch bits {
		case 0, 256:
			crv = elliptic.P256()
		case 384:
			crv = elliptic.P384()
		case 521:
			crv = elliptic.P521()
		default:
			return nil, nil, errors.New("unknown elliptic curve bit length, use one of 256, 384, 521")
		}
		key, err := ecdsa.GenerateKey(crv, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return key.Public(), key, nil
	default:
		return nil, nil, fmt.Errorf("unknown `alg`:%s for `use` = `enc`", alg)
	}
}
