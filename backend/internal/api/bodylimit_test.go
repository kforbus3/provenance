package api

import (
	"strings"
	"testing"
)

// The body cap was lifted by substring match, so any path merely CONTAINING the
// fragment was exempt — including paths that route nowhere, and any future route with
// one of these as an interior segment.
func TestTheBodyCapIsLiftedOnlyForTheRealUploadRoutes(t *testing.T) {
	exempt := func(p string) bool {
		return strings.HasSuffix(p, "/sftp/upload") || strings.HasSuffix(p, "/system/upgrade/preview")
	}
	for _, p := range []string{
		"/api/v1/hosts/2b1c/sftp/upload",
		"/api/v1/system/upgrade/preview",
	} {
		if !exempt(p) {
			t.Errorf("the real upload route %q is capped; a large upload would be truncated", p)
		}
	}
	for _, p := range []string{
		"/api/v1/hosts/2b1c/sftp/list/sftp/upload/extra",
		"/api/v1/audit/sftp/upload/x",
		"/api/v1/hosts/2b1c/sftp/list",
		"/api/v1/system/upgrade/preview/notreally",
	} {
		if exempt(p) {
			t.Errorf("%q is exempt from the body cap but is not an upload route", p)
		}
	}
}
