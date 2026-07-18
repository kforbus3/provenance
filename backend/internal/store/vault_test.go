package store

import "testing"

func TestAccessRank(t *testing.T) {
	if !(accessRank("manage") > accessRank("use") &&
		accessRank("use") > accessRank("view") &&
		accessRank("view") > accessRank("") &&
		accessRank("bogus") == 0) {
		t.Fatalf("access ranking wrong: manage=%d use=%d view=%d none=%d",
			accessRank("manage"), accessRank("use"), accessRank("view"), accessRank(""))
	}
}
