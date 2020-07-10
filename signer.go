// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package jwt

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/orivil/signature"
)

type Signer struct {
	alg string
	m   signature.SignMethod
}

func NewSigner(alg signature.Algorithm, privateKey []byte) (*Signer, error) {
	m, err := signature.NewSignMethod(alg, privateKey)
	if err != nil {
		return nil, err
	}
	return &Signer{
		alg: alg.String(),
		m:   m,
	}, nil
}

func (s *Signer) UnmarshalClaim(token []byte, c *Claim) error {
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return errors.New("jwt: token format incorrect")
	}
	header, payload, sig := parts[0], parts[1], parts[2]
	signData := append(append(header, '.'), payload...)
	var (
		err error
		ok  bool
	)
	sig, err = decodeURL(sig)
	if err != nil {
		return err
	}
	ok, err = s.m.Verify(sig, signData)
	if err != nil {
		return fmt.Errorf("jwt: verify signature got error: %v", err)
	}
	if !ok {
		return fmt.Errorf("jwt: verify signature failed")
	}
	return c.decode(payload)
}

func (s *Signer) MarshalClaim(c *Claim) ([]byte, error) {
	var header, claim, sig, token []byte
	var err error
	h := &Header{
		Algorithm: s.alg,
		Typ:       "JWT",
	}
	header, err = h.encode()
	if err != nil {
		return nil, err
	}
	claim, err = c.encode()
	if err != nil {
		return nil, err
	}
	token = append(header, '.')
	token = append(token, claim...)
	sig, err = s.m.Sign(token)
	if err != nil {
		return nil, err
	}
	sig = encodeURL(sig)
	token = append(token, '.')
	token = append(token, sig...)
	return token, nil
}
