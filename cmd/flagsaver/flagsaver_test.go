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

package flagsaver

import (
	"testing"
	"time"

	"flag"
)

var (
	intFlag      = flag.Int("int_flag", 123, "test integer flag")
	strFlag      = flag.String("str_flag", "foo", "test string flag")
	durationFlag = flag.Duration("duration_flag", 5*time.Second, "test duration flag")
)

// TestRestore checks that flags are saved and restore correctly.
// Checks are performed on flags with both their default values and with explicit values set.
// Only a subset of the possible flag types are currently tested.
func TestRestore(t *testing.T) {
	tests := []struct {
		// Test name
		name string
		// Name of flag to save and restore.
		flag string
		// The value the flag should have when saved. If empty, this indicates the flag should have its default value.
		oldValue string
		// The value the flag should have just before being restored to oldValue.
		newValue string
	}{
		{"RestoreDefaultIntValue", "int_flag", "", "666"},
		{"RestoreDefaultStrValue", "str_flag", "", "baz"},
		{"RestoreDefaultDurationValue", "duration_flag", "", "1m0s"},
		{"RestoreSetIntValue", "int_flag", "555", "666"},
		{"RestoreSetStrValue", "str_flag", "bar", "baz"},
		{"RestoreSetDurationValue", "duration_flag", "10s", "1m0s"},
	}

	for _, test := range tests {
		f := flag.Lookup(test.flag)
		if f == nil {
			t.Errorf("%s: flag.Lookup(%q) = nil, want not nil", test.name, test.flag)
			continue
		}

		if test.oldValue != "" {
			if err := flag.Set(test.flag, test.oldValue); err != nil {
				t.Errorf("%s: flag.Set(%q, %q) = error(%v), want nil", test.name, test.flag, test.oldValue, err)
				continue
			}
		} else {
			// Use the default value of the flag as the oldValue if none was set.
			test.oldValue = f.DefValue
		}

		func() {
			defer Save().Restore()
			flag.Set(test.flag, test.newValue)
			if gotValue := f.Value.String(); gotValue != test.newValue {
				t.Errorf("%s: flag.Lookup(%q).Value.String() = %q, want %q", test.name, test.flag, gotValue, test.newValue)
			}
		}()

		if gotValue := f.Value.String(); gotValue != test.oldValue {
			t.Errorf("%s: flag.Lookup(%q).Value.String() = %q, want %q", test.name, test.flag, gotValue, test.oldValue)
		}
	}
}
