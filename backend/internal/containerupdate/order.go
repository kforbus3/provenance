package containerupdate

import (
	"strings"

	"github.com/kforbus3/provenance/backend/internal/composefile"
	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// dependencyOrder sorts the images a host is about to take so that an image
// behind a service another one depends_on is applied first.
//
// A rollout over every available update applied nextcloud:35.0.2 and then
// linuxserver/mariadb:11.8.8 to the same stack, in that order, about a minute
// apart. Nextcloud runs its upgrade in its entrypoint; the database was recreated
// underneath it, the migration failed with "MySQL server has gone away", and
// Nextcloud kept itself in maintenance mode until somebody ran `occ upgrade` by
// hand. With the database first, the application's migration runs once, against
// a database that is not about to move.
//
// The compose files are the authority: depends_on is the operator saying which
// service needs which. Only stacks Provenance holds the text of can say so; an
// image on a host with no stack keeps its place. Otherwise the original order is
// kept, so a rollout with nothing to reorder behaves exactly as it did, and a
// dependency cycle (which compose itself refuses) falls back to it too.
func dependencyOrder(images []store.RolloutImage, stacks []store.ContainerStack,
	containers []models.Container) []store.RolloutImage {
	if len(images) < 2 {
		return images
	}

	// Which services each image backs, keyed "dir\x00service" so that two
	// projects that both call something "db" are not confused with each other.
	backs := make([]map[string]bool, len(images))
	for i, im := range images {
		backs[i] = map[string]bool{}
		for _, c := range containers {
			if c.Repository == im.Repository && c.Tag == im.FromTag && c.ComposeService != "" {
				backs[i][svcKey(c.ComposeDir, c.ComposeService)] = true
			}
		}
		for _, st := range stacks {
			if !st.Enabled {
				continue
			}
			for _, tag := range []string{im.FromTag, im.ToTag} {
				for _, svc := range composefile.ServicesFor(st.Compose, im.Repository, tag) {
					backs[i][svcKey(st.Path, svc)] = true
				}
			}
		}
	}

	// Every service each service needs, directly or through another.
	needs := map[string]map[string]bool{}
	for _, st := range stacks {
		if !st.Enabled {
			continue
		}
		direct := composefile.DependsOn(st.Compose)
		for svc := range direct {
			seen := map[string]bool{}
			walk := append([]string(nil), direct[svc]...)
			for len(walk) > 0 {
				dep := walk[0]
				walk = walk[1:]
				if seen[dep] {
					continue
				}
				seen[dep] = true
				walk = append(walk, direct[dep]...)
			}
			all := map[string]bool{}
			for dep := range seen {
				all[svcKey(st.Path, dep)] = true
			}
			needs[svcKey(st.Path, svc)] = all
		}
	}

	// before[j][i]: image i has to land before image j.
	before := make([]map[int]bool, len(images))
	for j := range images {
		before[j] = map[int]bool{}
		for svc := range backs[j] {
			for dep := range needs[svc] {
				for i := range images {
					if i != j && backs[i][dep] && !backs[j][dep] {
						before[j][i] = true
					}
				}
			}
		}
	}

	// Stable: each round takes the earliest image whose predecessors have all
	// landed. A cycle leaves nothing takeable; the rest then go in their original
	// order rather than not at all.
	out := make([]store.RolloutImage, 0, len(images))
	placed := make([]bool, len(images))
	for len(out) < len(images) {
		next := -1
		for j := range images {
			if placed[j] {
				continue
			}
			ready := true
			for i := range before[j] {
				if !placed[i] {
					ready = false
					break
				}
			}
			if ready {
				next = j
				break
			}
		}
		if next < 0 {
			for j := range images {
				if !placed[j] {
					placed[j] = true
					out = append(out, images[j])
				}
			}
			break
		}
		placed[next] = true
		out = append(out, images[next])
	}
	return out
}

func svcKey(dir, service string) string {
	return strings.TrimRight(dir, "/") + "\x00" + service
}
