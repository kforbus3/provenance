package stacks

import (
	"strings"
	"testing"
	"time"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// The real file from the outage, reduced to the part that decides it.
const keycloakCompose = `services:
  postgres:
    image: postgres:18.6-alpine
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
  keycloak:
    image: quay.io/keycloak/keycloak:26.7.4
    depends_on:
      postgres:
        condition: service_healthy
`

func running(service, repo, tag, dir string) models.Container {
	return models.Container{
		ComposeService: service, Repository: repo, Tag: tag, ComposeDir: dir,
		Image: repo + ":" + tag,
	}
}

func TestStatefulPinConflict(t *testing.T) {
	const dir = "/opt/stacks/keycloak"
	cases := []struct {
		name     string
		compose  string
		services []string
		running  []models.Container
		want     bool
		wantFrom string
		wantTo   string
	}{
		{
			name:    "the outage: the file pins a postgres major the data directory cannot take",
			compose: keycloakCompose,
			running: []models.Container{
				running("postgres", "postgres", "17.11-alpine", dir),
				running("keycloak", "quay.io/keycloak/keycloak", "26.7.4", dir),
			},
			want: true, wantFrom: "17.11-alpine", wantTo: "18.6-alpine",
		},
		{
			name:    "a patch move of the same major is an ordinary update",
			compose: strings.Replace(keycloakCompose, "18.6-alpine", "17.14-alpine", 1),
			running: []models.Container{running("postgres", "postgres", "17.11-alpine", dir)},
			want:    false,
		},
		{
			name:    "an application image is not stateful, whatever the version jump",
			compose: strings.Replace(keycloakCompose, "26.7.4", "99.0.0", 1),
			running: []models.Container{running("keycloak", "quay.io/keycloak/keycloak", "26.7.4", dir)},
			want:    false,
		},
		{
			name:     "a deploy narrowed to another service does not touch the database",
			compose:  keycloakCompose,
			services: []string{"keycloak"},
			running: []models.Container{
				running("postgres", "postgres", "17.11-alpine", dir),
				running("keycloak", "quay.io/keycloak/keycloak", "26.7.4", dir),
			},
			want: false,
		},
		{
			name:    "another project's postgres on the same host is not this stack's",
			compose: keycloakCompose,
			running: []models.Container{running("postgres", "postgres", "17.11-alpine", "/opt/stacks/other")},
			want:    false,
		},
		{
			name:    "a downgrade is a deliberate act, not this check's business",
			compose: strings.Replace(keycloakCompose, "18.6-alpine", "16.4-alpine", 1),
			running: []models.Container{running("postgres", "postgres", "17.11-alpine", dir)},
			want:    false,
		},
		{
			name:    "an interpolated tag is resolved on the host, so nothing is claimed",
			compose: strings.Replace(keycloakCompose, "18.6-alpine", "${PG_TAG}", 1),
			running: []models.Container{running("postgres", "postgres", "17.11-alpine", dir)},
			want:    false,
		},
		{
			name:    "a service the host is not running yet cannot conflict",
			compose: keycloakCompose,
			running: []models.Container{},
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := statefulPinConflict(tc.compose, tc.services, tc.running, dir)
			if tc.want && got == nil {
				t.Fatalf("no conflict reported; this deploy takes the stack down")
			}
			if !tc.want && got != nil {
				t.Fatalf("refused a deploy it should allow: %v", got)
			}
			if !tc.want {
				return
			}
			if got.FromTag != tc.wantFrom || got.ToTag != tc.wantTo {
				t.Errorf("conflict names %s -> %s, want %s -> %s",
					got.FromTag, got.ToTag, tc.wantFrom, tc.wantTo)
			}
			// The message has to carry the way out, or it is just a refusal.
			if !strings.Contains(got.Error(), "pg_upgrade") {
				t.Errorf("the refusal does not name the migration it needs: %v", got)
			}
			if !strings.Contains(got.Error(), got.Service) {
				t.Errorf("the refusal does not name the service: %v", got)
			}
		})
	}
}

func TestComposeImagesReadsOnlyServiceImages(t *testing.T) {
	compose := `services:
  web:
    image: "nginx:1.27"   # quoted, with a trailing comment
  db:
    image: postgres:17.11-alpine
  sidecar:
    build: ./sidecar
volumes:
  image: not-a-service
`
	got := composeImages(compose)
	if got["web"] != "nginx:1.27" {
		t.Errorf("quoted image with a comment parsed as %q", got["web"])
	}
	if got["db"] != "postgres:17.11-alpine" {
		t.Errorf("db image parsed as %q", got["db"])
	}
	if _, ok := got["sidecar"]; ok {
		t.Error("a built service has no image and must not appear")
	}
	if len(got) != 2 {
		t.Errorf("read %d images from a file with two: %v — a key outside services: was "+
			"taken for a service", len(got), got)
	}
}

func TestSplitImageKeepsARegistryPort(t *testing.T) {
	for _, tc := range []struct{ ref, repo, tag string }{
		{"postgres:17.11-alpine", "postgres", "17.11-alpine"},
		{"registry.example.com:5000/app", "registry.example.com:5000/app", "latest"},
		{"registry.example.com:5000/app:1.2", "registry.example.com:5000/app", "1.2"},
		{"quay.io/keycloak/keycloak:26.7.4", "quay.io/keycloak/keycloak", "26.7.4"},
		{"nginx", "nginx", "latest"},
		{"nginx@sha256:abc", "nginx", "latest"},
		{"${IMAGE}", "", ""},
	} {
		repo, tag := splitImage(tc.ref)
		if repo != tc.repo || tag != tc.tag {
			t.Errorf("%q split to (%q, %q), want (%q, %q)", tc.ref, repo, tag, tc.repo, tc.tag)
		}
	}
}

func TestAlreadyFailedRevision(t *testing.T) {
	rev := func(n int) *int { return &n }
	when := time.Date(2026, 9, 20, 2, 50, 0, 0, time.UTC)

	cases := []struct {
		name string
		st   store.ContainerStack
		want bool
	}{
		{
			name: "the host failed on exactly this revision",
			st: store.ContainerStack{
				Revision: 3, Deployed: rev(3), DeployState: DeployStateFailed,
				Hostname: "identity", DeployedAt: &when,
				DeployDetail: "dependency failed to start: container keycloak-db is unhealthy\nmore",
			},
			want: true,
		},
		{
			name: "the definition has been edited since it failed",
			st: store.ContainerStack{
				Revision: 4, Deployed: rev(3), DeployState: DeployStateFailed,
			},
			want: false,
		},
		{
			name: "the last deploy succeeded",
			st: store.ContainerStack{
				Revision: 3, Deployed: rev(3), DeployState: DeployStateDeployed,
			},
			want: false,
		},
		{
			name: "never deployed",
			st:   store.ContainerStack{Revision: 1},
			want: false,
		},
		{
			name: "a deploy is in flight",
			st: store.ContainerStack{
				Revision: 3, Deployed: rev(3), DeployState: DeployStateDeploying,
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := alreadyFailed(&tc.st)
			if tc.want != (got != nil) {
				t.Fatalf("alreadyFailed = %v, want refusal=%v", got, tc.want)
			}
			if !tc.want {
				return
			}
			msg := got.Error()
			for _, want := range []string{"revision 3", "identity", "02:50", "not changed"} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal does not mention %q — an operator cannot tell "+
						"what already happened: %s", want, msg)
				}
			}
			// The stored output's first line is what the dialog shows; a wall of text
			// is not.
			if strings.Contains(got.Detail, "\n") || !strings.Contains(got.Detail, "keycloak-db") {
				t.Errorf("detail is not the first line of the failure: %q", got.Detail)
			}
		})
	}
}
