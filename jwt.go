// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

var NowFunc = time.Now

type Claim struct {
	ExpirationTime int64       `json:"exp,omitempty"` // 过期时间
	NotBefore      int64       `json:"nbf,omitempty"` // token 启用时间
	IssuedAt       int64       `json:"iat,omitempty"` // token 签发时间
	Issuer         string      `json:"iss,omitempty"` // 签发人
	Audience       string      `json:"aud,omitempty"` // 受众
	Principal      string      `json:"prn,omitempty"` // 主题
	JwtID          string      `json:"jti,omitempty"` // jwt id
	Private        interface{} `json:"pri,omitempty"` // 用户自定义数据
}

func (c *Claim) Verify() bool {
	now := NowFunc().Unix()
	if c.ExpirationTime > 0 {
		if c.ExpirationTime < now {
			return false
		}
	}
	if c.NotBefore > 0 {
		if now < c.NotBefore {
			return false
		}
	}
	if c.IssuedAt > 0 {
		if now < c.IssuedAt {
			return false
		}
	}
	return true
}

func (c *Claim) decode(payload []byte) (err error) {
	var data []byte
	data, err = decodeURL(payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, c)
}

func (c *Claim) encode() (payload []byte, err error) {
	now := NowFunc()
	if c.IssuedAt == 0 {
		c.IssuedAt = now.Unix()
	}
	if c.ExpirationTime == 0 {
		c.ExpirationTime = now.Add(2 * time.Hour).Unix()
	}
	if c.ExpirationTime < c.IssuedAt {
		return nil, fmt.Errorf("jwt: invalid ExpirationTime = %v; must be later than IssuedAt = %v", c.ExpirationTime, c.IssuedAt)
	}
	var src []byte
	src, err = json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return encodeURL(src), nil
}

// Header represents the header for the signed JWS payloads.
type Header struct {
	// The algorithm used for signature.
	Algorithm string `json:"alg"`

	// Represents the token type.
	Typ string `json:"typ"`
}

func (h *Header) encode() ([]byte, error) {
	src, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	return encodeURL(src), nil
}

func encodeURL(src []byte) []byte {
	enc := base64.RawURLEncoding
	buf := make([]byte, enc.EncodedLen(len(src)))
	enc.Encode(buf, src)
	return buf
}

func decodeURL(src []byte) ([]byte, error) {
	enc := base64.RawURLEncoding
	buf := make([]byte, enc.DecodedLen(len(src)))
	n, err := enc.Decode(buf, []byte(src))
	return buf[:n], err
}
