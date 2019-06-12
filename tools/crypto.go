package tools

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

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
