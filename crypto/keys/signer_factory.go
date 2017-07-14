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

package keys

import (
	"context"
	"crypto"

	"github.com/golang/protobuf/proto"
	"github.com/google/trillian/crypto/keyspb"
)

// ProtoGenerator creates a new private key based on a key specification.
// It returns a proto that can be passed to a ProtoHandler to get a crypto.Signer.
type ProtoGenerator func(context.Context, *keyspb.Specification) (proto.Message, error)

// SignerFactory produces a crypto.Signer from a protobuf message describing a key.
// If SignerFactory.Generate != nil, it can also generate new private keys.
type SignerFactory struct {
	// Generate creates a new private key based on a key specification.
	// It returns a proto that can be passed to NewSigner() to get a crypto.Signer.
	// If nil, key generation will not be possible.
	Generate ProtoGenerator
}

// NewSignerFactory returns a SignerFactory with no ProtoHandlers or ProtoGenerator.
func NewSignerFactory() SignerFactory {
	return SignerFactory{}
}

// NewSigner uses the information in pb to return a crypto.Signer.
// pb must be a keyspb.PEMKeyFile, keyspb.PrivateKey or keyspb.PKCS11Config.
func (f SignerFactory) NewSigner(ctx context.Context, keyProto proto.Message) (crypto.Signer, error) {
	return NewSigner(ctx, keyProto)
}
