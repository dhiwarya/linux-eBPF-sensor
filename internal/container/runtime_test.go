// SPDX-License-Identifier: Apache-2.0

package container

import "testing"

func TestTargetValidate(t *testing.T) {
	for _, tc := range []struct {
		t  Target
		ok bool
	}{
		{Target{Name: "web"}, true},
		{Target{ID: "abc123"}, true},
		{Target{Label: "app=web"}, true},
		{Target{}, false},
		{Target{Name: "web", ID: "abc"}, false},
		{Target{Label: "novalue"}, false},
	} {
		if err := tc.t.Validate(); (err == nil) != tc.ok {
			t.Errorf("Validate(%+v) = %v, want ok=%v", tc.t, err, tc.ok)
		}
	}
}

func TestTargetMatches(t *testing.T) {
	c := Container{ID: "abcdef0123456789", Name: "web", Labels: map[string]string{"app": "web", "tier": "front"}}
	for _, tc := range []struct {
		t    Target
		want bool
	}{
		{Target{Name: "web"}, true},
		{Target{Name: "/web"}, true},
		{Target{Name: "we"}, false},
		{Target{ID: "abcdef"}, true},
		{Target{ID: "abcdef0123456789"}, true},
		{Target{ID: "bcdef"}, false},
		{Target{Label: "app=web"}, true},
		{Target{Label: "app=db"}, false},
		{Target{Label: "missing=x"}, false},
	} {
		if got := tc.t.Matches(c); got != tc.want {
			t.Errorf("%+v.Matches = %v, want %v", tc.t, got, tc.want)
		}
	}
}
