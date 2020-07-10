# golang JWT(JSON Web Token) tool

Package `jwt` implemented the [RFC7519](https://tools.ietf.org/html/rfc7519)

Usage:
```go
package main

import (
	"fmt"
	"github.com/orivil/jwt"
	"github.com/orivil/signature"
	"time"
)

func main() {
    // private structure
	type user struct {
		ID int `json:"id"`
	}
	signer, err := jwt.NewSigner(signature.HS256, []byte("secret key"))
	if err != nil {
		panic(err)
	}

	// marshal token
	var token []byte
	token, err = signer.MarshalClaim(&jwt.Claim{
		ExpirationTime: jwt.NowFunc().Add(100 * time.Hour).Unix(),
		Private:        &user{ID: 111},
	})
	if err != nil {
		panic(err)
	}

	// unmarshal token
	usr := &user{}
	claim := &jwt.Claim{Private: usr}
	err = signer.UnmarshalClaim(token, claim)
	if err != nil {
		panic(err)
	}
	fmt.Println(usr.ID == 111)

	// test expiration time
	fmt.Println(claim.Verify() == true)
	// move time forward
	jwt.NowFunc = func() time.Time {
		return time.Now().Add(101 * time.Hour)
	}
	fmt.Println(claim.Verify() == false)

	// Output:
	// true
	// true
	// true
}
```