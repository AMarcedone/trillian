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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/trillian/crypto/keyspb"
)

const (
	// DefaultRsaKeySizeInBits is the size of an RSA key generated by this package, in bits, if not overridden.
	DefaultRsaKeySizeInBits = 2048

	// MinRsaKeySizeInBits is the smallest RSA key that this package will generate.
	MinRsaKeySizeInBits = 2048
)

// Generate creates a new private key based on a key specification.
// It returns a proto that can be passed to a ProtoHandler to get a crypto.Signer.
// Defaults to nil; should be set before use.
var Generate func(context.Context, *keyspb.Specification) (proto.Message, error)

// NewFromSpec generates a new private key based on a key specification.
// If an RSA key is specified, the key size must be at least MinRsaKeySizeInBits.
func NewFromSpec(spec *keyspb.Specification) (crypto.Signer, error) {
	switch params := spec.GetParams().(type) {
	case *keyspb.Specification_EcdsaParams:
		curve := ECDSACurveFromParams(params.EcdsaParams)
		if curve == nil {
			return nil, fmt.Errorf("unsupported ECDSA curve: %s", params.EcdsaParams.GetCurve())
		}

		return ecdsa.GenerateKey(curve, rand.Reader)
	case *keyspb.Specification_RsaParams:
		bits := int(params.RsaParams.GetBits())
		if bits == 0 {
			bits = DefaultRsaKeySizeInBits
		}
		if bits < MinRsaKeySizeInBits {
			return nil, fmt.Errorf("minimum RSA key size is %v bits, got %v bits", MinRsaKeySizeInBits, bits)
		}

		return rsa.GenerateKey(rand.Reader, bits)
	default:
		return nil, fmt.Errorf("unsupported keygen params type: %T", params)
	}
}

// ECDSACurveFromParams returns the curve specified by the given parameters.
// Returns nil if the curve is not supported.
func ECDSACurveFromParams(params *keyspb.Specification_ECDSA) elliptic.Curve {
	switch params.GetCurve() {
	case keyspb.Specification_ECDSA_DEFAULT_CURVE:
		return elliptic.P256()
	case keyspb.Specification_ECDSA_P256:
		return elliptic.P256()
	case keyspb.Specification_ECDSA_P384:
		return elliptic.P384()
	case keyspb.Specification_ECDSA_P521:
		return elliptic.P521()
	}
	return nil
}
