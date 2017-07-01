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
	"fmt"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/trillian/crypto/keyspb"
)

// ProtoHandler uses the information in a protobuf message to obtain a crypto.Signer.
// For example, the protobuf message may contain a key or identify where a key can be found.
type ProtoHandler func(context.Context, proto.Message) (crypto.Signer, error)

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

	// handlers convert a protobuf message into a crypto.Signer.
	handlers map[string]ProtoHandler
}

// NewSignerFactory returns a SignerFactory with no ProtoHandlers or ProtoGenerator.
func NewSignerFactory() SignerFactory {
	return SignerFactory{
		handlers: make(map[string]ProtoHandler),
	}
}

// AddHandler enables the SignerFactory to transform a protobuf message of the same
// type as keyProto into a crypto.Signer by invoking handler.
// The keyProto need only be an empty example of the type of protobuf message that
// the handler can process - only its type is examined.
// If a handler for this type of protobuf message has already been added, it will
// be replaced.
func (f SignerFactory) AddHandler(keyProto proto.Message, handler ProtoHandler) {
	keyProtoType := proto.MessageName(keyProto)

	if _, alreadyExists := f.handlers[keyProtoType]; alreadyExists {
		glog.Warningf("Overridding ProtoHandler for protobuf %q", keyProtoType)
	}

	f.handlers[keyProtoType] = handler
}

// RemoveHandler removes a previously-added protobuf message handler.
// See SignerFactory.AddHandler().
func (f SignerFactory) RemoveHandler(keyProto proto.Message) {
	delete(f.handlers, proto.MessageName(keyProto))
}

// NewSigner uses the information in pb to return a crypto.Signer.
// pb must be a keyspb.PEMKeyFile, keyspb.PrivateKey or keyspb.PKCS11Config.
func (f SignerFactory) NewSigner(ctx context.Context, keyProto proto.Message) (crypto.Signer, error) {
	keyProtoType := proto.MessageName(keyProto)

	if handler, ok := f.handlers[keyProtoType]; ok {
		return handler(ctx, keyProto)
	}

	return nil, fmt.Errorf("no ProtoHandler registered for protobuf %q", keyProtoType)
}
