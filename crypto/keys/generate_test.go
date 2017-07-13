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
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	"github.com/google/trillian/crypto/keyspb"
)

func TestNewFromSpec(t *testing.T) {
	for _, test := range []struct {
		desc    string
		keygen  *keyspb.Specification
		wantErr bool
	}{
		{
			desc: "ECDSA with default params",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_EcdsaParams{},
			},
		},
		{
			desc: "ECDSA with explicit params",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_EcdsaParams{
					EcdsaParams: &keyspb.Specification_ECDSA{
						Curve: keyspb.Specification_ECDSA_P521,
					},
				},
			},
		},
		{
			desc: "RSA with default params",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_RsaParams{},
			},
		},
		{
			desc: "RSA with explicit params",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_RsaParams{
					RsaParams: &keyspb.Specification_RSA{
						Bits: 4096,
					},
				},
			},
		},
		{
			desc: "RSA with negative key size",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_RsaParams{
					RsaParams: &keyspb.Specification_RSA{
						Bits: -4096,
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "RSA with insufficient key size",
			keygen: &keyspb.Specification{
				Params: &keyspb.Specification_RsaParams{
					RsaParams: &keyspb.Specification_RSA{
						Bits: MinRsaKeySizeInBits - 1,
					},
				},
			},
			wantErr: true,
		},
		{
			desc:    "No params",
			keygen:  &keyspb.Specification{},
			wantErr: true,
		},
		{
			desc:    "Nil KeySpec",
			wantErr: true,
		},
	} {
		key, err := NewFromSpec(test.keygen)
		if gotErr := err != nil; gotErr != test.wantErr {
			t.Errorf("%v: NewFromSpec() = (_, %v), want err? %v", test.desc, err, test.wantErr)
			continue
		} else if gotErr {
			continue
		}

		switch params := test.keygen.Params.(type) {
		case *keyspb.Specification_EcdsaParams:
			switch key := key.(type) {
			case *ecdsa.PrivateKey:
				wantCurve := curveFromParams(params.EcdsaParams)
				if wantCurve.Params().Name != key.Params().Name {
					t.Errorf("%v: NewFromSpec() => ECDSA key on %v curve, want %v curve", test.desc, key.Params().Name, wantCurve.Params().Name)
				}
			default:
				t.Errorf("%v: NewFromSpec() = (%T, nil), want *ecdsa.PrivateKey", test.desc, key)
			}
		case *keyspb.Specification_RsaParams:
			switch key := key.(type) {
			case *rsa.PrivateKey:
				wantBits := defaultRsaKeySizeInBits
				if params.RsaParams.GetBits() != 0 {
					wantBits = int(params.RsaParams.GetBits())
				}

				if got, want := key.N.BitLen(), wantBits; got != want {
					t.Errorf("%v: NewFromSpec() => %v-bit RSA key, want %v-bit", test.desc, got, want)
				}
			default:
				t.Errorf("%v: NewFromSpec() = (%T, nil), want *rsa.PrivateKey", test.desc, key)
			}
		}
	}
}
