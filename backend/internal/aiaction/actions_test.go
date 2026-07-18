package aiaction

import (
	"reflect"
	"testing"
)

func TestApplyTags(t *testing.T) {
	cases := []struct {
		current, add, remove, want []string
	}{
		{[]string{"prod", "web"}, []string{"legacy"}, nil, []string{"prod", "web", "legacy"}},
		{[]string{"prod", "web"}, nil, []string{"web"}, []string{"prod"}},
		{[]string{"prod"}, []string{"prod"}, nil, []string{"prod"}},                        // no dup
		{[]string{"prod", "web"}, []string{"DB"}, []string{"WEB"}, []string{"prod", "db"}}, // case-insensitive
		{[]string{"a", "b"}, []string{"c"}, []string{"a"}, []string{"b", "c"}},
		{nil, []string{"x", "x"}, nil, []string{"x"}},
	}
	for i, c := range cases {
		got := applyTags(c.current, c.add, c.remove)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("case %d: applyTags(%v,%v,%v) = %v, want %v", i, c.current, c.add, c.remove, got, c.want)
		}
	}
}

func TestCleanTags(t *testing.T) {
	got := cleanTags([]string{" Prod ", "prod", "", "WEB", "web"})
	want := []string{"prod", "web"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cleanTags = %v, want %v", got, want)
	}
}

func TestDescribeTargets(t *testing.T) {
	if d := describeTargets("web-01", []string{"web-01"}); d != "host web-01" {
		t.Errorf("single host = %q", d)
	}
	d := describeTargets("group prod", []string{"a", "b"})
	if d != "2 host(s) in group prod (a, b)" {
		t.Errorf("group = %q", d)
	}
}
