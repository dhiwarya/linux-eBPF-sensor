// SPDX-License-Identifier: Apache-2.0

package event

import (
	"reflect"
	"testing"
)

func TestSplitArgv(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", []string{}},
		{"only nul", "\x00", []string{}},
		{"single", "ls\x00", []string{"ls"}},
		{"multiple", "ls\x00-la\x00/tmp\x00", []string{"ls", "-la", "/tmp"}},
		{"empty arg in middle", "echo\x00\x00x\x00", []string{"echo", "", "x"}},
		{"empty last arg", "prog\x00\x00", []string{"prog", ""}},
		{"spaces kept inside arg", "bash\x00-c\x00echo hi\x00", []string{"bash", "-c", "echo hi"}},
		{"truncated mid-arg", "cat\x00/very/long/pa", []string{"cat", "/very/long/pa"}},
		{"truncated right after nul", "cat\x00a\x00", []string{"cat", "a"}},
		{"non-utf8 kept", "x\x00\xff\xfe\x00", []string{"x", "\xff\xfe"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitArgv([]byte(tt.in))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitArgv(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCString(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"bash\x00\x00\x00", "bash"},
		{"no-terminator", "no-terminator"},
		{"a\x00garbage", "a"},
	}
	for _, tt := range tests {
		if got := CString([]byte(tt.in)); got != tt.want {
			t.Errorf("CString(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
