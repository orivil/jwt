// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package jwt_test

import (
	"github.com/orivil/jwt"
	"github.com/orivil/signature"
	"testing"
	"time"
)

// 3547 ns/op
func BenchmarkSigner_MarshalClaim(b *testing.B) {
	signer, err := jwt.NewSigner(signature.HS256, []byte("secret key"))
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		_, err = signer.MarshalClaim(&jwt.Claim{})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// 4751 ns/op
func BenchmarkSigner_UnmarshalClaim(b *testing.B) {
	signer, err := jwt.NewSigner(signature.HS256, []byte("secret key"))
	if err != nil {
		b.Fatal(err)
	}
	pv := "some custom value"
	token, err := signer.MarshalClaim(&jwt.Claim{
		ExpirationTime: jwt.NowFunc().Add(100 * time.Hour).Unix(),
		Private:        pv,
	})
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		claims := &jwt.Claim{}
		err = signer.UnmarshalClaim(token, claims)
		if err != nil {
			b.Fatal(err)
		}
		if claims.Private != pv {
			b.Fatal("private value got error")
		}
	}
}
