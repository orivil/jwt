// Copyright 2020 orivil.com. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found at https://mit-license.org.

package jwt_service

import (
	"github.com/orivil/jwt"
	"github.com/orivil/service"
	"github.com/orivil/services/cfg"
)

type Service struct {
	cs    *cfg.Service
	cname string
	self  service.Provider
}

func (s *Service) New(container *service.Container) (interface{}, error) {
	envs, err := s.cs.Get(container)
	if err != nil {
		return nil, err
	}
	env := &Env{}
	err = envs.UnmarshalSub(s.cname, env)
	if err != nil {
		return nil, err
	}
	return jwt.NewSigner(env.Alg, []byte(env.PrivateKey))
}

func (s *Service) Get(container *service.Container) (*jwt.Signer, error) {
	signer, err := container.Get(&s.self)
	if err != nil {
		return nil, err
	} else {
		return signer.(*jwt.Signer), nil
	}
}

func NewService(configNamespace string, cs *cfg.Service) *Service {
	s := &Service{
		cs:    cs,
		cname: configNamespace,
	}
	s.self = s
	return s
}
