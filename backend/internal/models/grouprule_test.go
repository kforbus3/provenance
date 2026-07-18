package models

import "testing"

func TestGroupRuleEmpty(t *testing.T) {
	if !(*GroupRule)(nil).Empty() {
		t.Fatal("nil rule should be empty")
	}
	if !(&GroupRule{}).Empty() {
		t.Fatal("zero-value rule should be empty")
	}
	cases := []GroupRule{
		{Environment: "production"},
		{TagsAll: []string{"web"}},
		{TagsAny: []string{"db"}},
		{OSContains: "ubuntu"},
		{HostnameContains: "web"},
	}
	for i, c := range cases {
		if c.Empty() {
			t.Fatalf("case %d should not be empty: %+v", i, c)
		}
	}
}
