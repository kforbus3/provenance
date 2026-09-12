package containerupdate

import (
	"context"
	"encoding/json"
	"strings"
)

// Provenance's own containers are upgraded by bundle, never by a container
// rollout.
//
// The bundle path exists because upgrading this application is not the same
// operation as pulling a newer image. A bundle is signature-verified, takes a
// pre-upgrade database backup, applies migrations in order, keeps a :rollback
// anchor, and restarts the stack in a sequence that survives the backend
// replacing itself. A container rollout does none of that.
//
// Worse, a rollout of this application's own containers cannot even report what
// it did: the backend running the rollout IS what gets restarted, so the result
// is never written and the rollout is left mid-flight forever.
//
// This is not only about this product's own images -- those are built locally and
// already excluded, having no registry digest to compare against. It is about the
// third-party containers the application is MADE of. On a live instance those are
// postgres:16-alpine, redis:7-alpine and guacamole/guacd:1.5.5: the database this
// server is talking to, the cache holding its sessions, and the daemon carrying
// its remote-desktop connections. All three are ordinary registry images, all
// three would otherwise be offered for update, and restarting the database under
// the running backend is the least bad thing that would happen.
//
// They stay VISIBLE, deliberately. What the instance is running, and what is
// wrong with those images, is exactly what an operator should be able to see --
// and the vulnerability scanning of postgres or guacd is some of the most useful
// it does. Only updating them this way is refused.

// selfProjectKey is the settings key holding this instance's compose project.
const selfProjectKey = "containers.selfProject"

// defaultSelfProject is the compose project this application ships as.
//
// Overridable because the project name comes from whoever ran compose -- a
// deployment that renamed it would otherwise have its own database offered for
// update, which is the failure this exists to prevent, silently.
const defaultSelfProject = "fleet-terminal"

// SettingsReader is the slice of the store this needs.
type SettingsReader interface {
	GetSetting(ctx context.Context, key string) (json.RawMessage, error)
}

// selfProject returns the compose project that is this application.
func selfProject(ctx context.Context, st SettingsReader) string {
	if st != nil {
		if raw, err := st.GetSetting(ctx, selfProjectKey); err == nil && len(raw) > 0 {
			var v string
			if json.Unmarshal(raw, &v) == nil && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return defaultSelfProject
}

// isSelfContainer reports whether a container is part of this application.
func isSelfContainer(project, composeProject, image string) bool {
	if project == "" {
		return false
	}
	if composeProject == project {
		return true
	}
	// A container started outside compose, or whose labels were not collected,
	// still belongs to this application if it runs one of its images. Locally
	// built ones are named <project>-<component>.
	return strings.HasPrefix(image, project+"-")
}
