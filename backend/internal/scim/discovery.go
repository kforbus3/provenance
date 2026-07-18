package scim

import (
	"net/http"
	"strings"
)

// serviceProviderConfig advertises which SCIM features this endpoint supports
// (RFC 7643 §5). We support create/update/patch/delete of Users; no bulk, no
// password change, no ETag, and bearer-token auth.
func (h *handler) serviceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": strings.TrimRight(h.d.Cfg.PublicURL, "/") + "/help/automation",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": 200},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "Bearer Token",
			"description": "Static bearer token issued from the Fleet admin console",
			"primary":     true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": h.baseURL() + "/ServiceProviderConfig"},
	})
}

// resourceTypes lists the SCIM resource types this endpoint exposes (Users only).
func (h *handler) resourceTypes(w http.ResponseWriter, r *http.Request) {
	userType := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		"id":          "User",
		"name":        "User",
		"endpoint":    "/Users",
		"description": "User Account",
		"schema":      userSchema,
		"meta":        map[string]any{"resourceType": "ResourceType", "location": h.baseURL() + "/ResourceTypes/User"},
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 1,
		"startIndex":   1,
		"itemsPerPage": 1,
		"Resources":    []any{userType},
	})
}

// schemas returns the core User schema definition (RFC 7643 §7). Kept minimal —
// the attributes Fleet actually maps.
func (h *handler) schemas(w http.ResponseWriter, r *http.Request) {
	attr := func(name, typ string, multi bool) map[string]any {
		return map[string]any{
			"name": name, "type": typ, "multiValued": multi,
			"required": false, "caseExact": false, "mutability": "readWrite",
			"returned": "default", "uniqueness": "none",
		}
	}
	userDef := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		"id":          userSchema,
		"name":        "User",
		"description": "User Account",
		"attributes": []map[string]any{
			func() map[string]any {
				a := attr("userName", "string", false)
				a["required"] = true
				a["uniqueness"] = "server"
				return a
			}(),
			attr("displayName", "string", false),
			attr("active", "boolean", false),
			attr("emails", "complex", true),
			attr("name", "complex", false),
		},
		"meta": map[string]any{"resourceType": "Schema", "location": h.baseURL() + "/Schemas/" + userSchema},
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 1,
		"startIndex":   1,
		"itemsPerPage": 1,
		"Resources":    []any{userDef},
	})
}
