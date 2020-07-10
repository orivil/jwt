// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package jwt_service

import "github.com/orivil/signature"

/*
# 签名配置
[signature]
# 签名算法, HS256=0(默认), HS384=1, HS512=2, ES256=3, ES384=4, ES512=5, RS256=6, RS384=7, RS512=8
alg = 0
# 私有 key, 该值如果泄露, 意味着所有签名数据都可以被篡改
private_key = "your secret key"
*/
type Env struct {
	Alg        signature.Algorithm `toml:"alg"`
	PrivateKey string              `toml:"private_key"`
}
