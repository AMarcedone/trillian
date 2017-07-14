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

package main

import (
	"flag"

	"github.com/google/trillian/crypto/keys/pkcs11"
	"github.com/google/trillian/crypto/keyspb"
)

var pkcs11ModulePath = flag.String("pkcs11_module_path", "", "Path to the PKCS#11 module to use for keys that use the PKCS#11 interface")

func init() {
	signerFactory.AddHandler(&keyspb.PKCS11Config{}, pkcs11.ProtoHandler(pkcs11ModulePath))
}