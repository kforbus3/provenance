package hosts

import (
	"reflect"
	"testing"
)

func TestCleanTags(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"trims and drops empty", []string{" prod ", "", "  "}, []string{"prod"}},
		{"dedupes preserving order", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"nil in empty out", nil, []string{}},
		{"already clean", []string{"web", "db"}, []string{"web", "db"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cleanTags(c.in); !reflect.DeepEqual(got, c.want) {
				t.Errorf("cleanTags(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
