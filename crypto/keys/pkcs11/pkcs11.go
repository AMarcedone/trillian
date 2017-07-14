// +build pkcs11

// Copyright 2017 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkcs11

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/letsencrypt/pkcs11key"
)

// ProtoHandler returns a ProtoHandler configured to use the specified PKCS#11 modulePath.
// This ProtoHandler will retrieve keys as specified by PKCS11Config proto messages.
// It can be passed to SignerFactory.AddHandler().
func ProtoHandler(modulePath *string) keys.ProtoHandler {
	return func(ctx context.Context, pb proto.Message) (crypto.Signer, error) {
		if cfg, ok := pb.(*keyspb.PKCS11Config); ok {
			return FromConfig(*modulePath, cfg)
		}
		return nil, fmt.Errorf("pkcs11: got %T, want *keyspb.PKCS11Config", pb)
	}
}

// FromConfig returns a crypto.Signer that uses a PKCS#11 interface.
func FromConfig(modulePath string, config *keyspb.PKCS11Config) (crypto.Signer, error) {
	if modulePath == "" {
		return nil, errors.New("pkcs11: No module path")
	}

	pubKeyPEM := config.GetPublicKey()
	pubKey, err := keys.NewFromPublicPEM(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: error loading public key from %q: %v", pubKeyPEM, err)
	}

	return pkcs11key.New(modulePath, config.GetTokenLabel(), config.GetPin(), pubKey)
}
