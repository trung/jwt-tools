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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"gopkg.in/square/go-jose.v2"

	"gopkg.in/square/go-jose.v2/jwt"
)

type JSONWebKeySetProviderFunc func() (*jose.JSONWebKeySet, error)
type DecryptionKeyProviderFunc func() (interface{}, error)
type VerificationOptions struct {
	JkwsFunc          JSONWebKeySetProviderFunc
	DecryptionKeyFunc DecryptionKeyProviderFunc
}

func DecodeJWT(tokenReader io.Reader, isJWS, isJWE bool, opts *VerificationOptions) (interface{}, interface{}, error) {
	tokenData, err := ioutil.ReadAll(tokenReader)
	if err != nil {
		return nil, nil, err
	}
	if !isJWE && !isJWS {
		return nil, nil, fmt.Errorf("unsupported token. Token must be with JWS and/or JWE")
	}
	parseFunc := func(string) (*jwt.JSONWebToken, error) {
		return nil, fmt.Errorf("unimplemented")
	}
	if isJWS && !isJWE {
		parseFunc = jwt.ParseSigned
	}
	if isJWE && !isJWS {
		parseFunc = jwt.ParseEncrypted
	}
	if isJWS && isJWE {
		if opts == nil || opts.DecryptionKeyFunc == nil {
			return nil, nil, fmt.Errorf("missing decryption key function")
		}
		parseFunc = func(s string) (token *jwt.JSONWebToken, e error) {
			t, err := jwt.ParseSignedAndEncrypted(s)
			if err != nil {
				return nil, err
			}
			key, err := opts.DecryptionKeyFunc()
			if err != nil {
				return nil, err
			}
			return t.Decrypt(key)
		}
	}

	token := string(tokenData)
	jwtToken, err := parseFunc(token)
	if err != nil {
		return nil, nil, err
	}
	var payload map[string]interface{}
	if opts != nil && opts.JkwsFunc != nil {
		jsonWebKeySet, err := opts.JkwsFunc()
		if err != nil {
			return nil, nil, err
		}
		if err := jwtToken.Claims(jsonWebKeySet, &payload); err != nil {
			return nil, nil, err
		}
	} else {
		if err := jwtToken.UnsafeClaimsWithoutVerification(&payload); err != nil {
			return nil, nil, err
		}
	}
	headersB64 := strings.Split(token, ".")[0]
	var header map[string]interface{}
	if err := json.NewDecoder(base64.NewDecoder(base64.StdEncoding, strings.NewReader(headersB64))).Decode(&header); err != nil {
		return nil, nil, err
	}
	return header, payload, nil
}
