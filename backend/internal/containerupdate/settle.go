package containerupdate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kforbus3/provenance/backend/internal/hostexec"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// SettleTimeout bounds how long a host waits for an updated container to finish
// starting before its next image is applied.
const SettleTimeout = 20 * time.Minute

// settleInterval is how often a settling container is read back.
const settleInterval = 10 * time.Second

// settle waits until the containers just moved onto r's target have finished
// starting, before the same host is given its next image.
//
// "Running the target" is what verification proves, and for most images it is the
// whole story. It is not for an image that migrates on start: nextcloud's
// entrypoint ran `occ upgrade` for a minute and more after the container was up,
// and in that minute the rollout moved on to the mariadb the same stack runs and
// recreated it -- "MySQL server has gone away", "Update failed", maintenance mode.
// The container's health check was saying so the whole time: status.php does not
// answer during the upgrade, so it was still "starting".
//
// So the healthcheck verdict is the signal:
//   - "starting": not finished; wait, up to SettleTimeout.
//   - "healthy", or no healthcheck at all: done; carry on.
//   - "unhealthy", or no longer running: stop this host. Applying more images on
//     top of a service that has just gone bad is what applyAll refuses to do on a
//     failed deploy, for the same reason.
//
// Only between images on one host. The last image has nothing behind it to
// collide with, and the soak re-check is what judges it.
func (e *Engine) settle(ctx context.Context, r store.UpdateRollout, hostID uuid.UUID) error {
	h, err := e.store.GetHost(ctx, hostID)
	if err != nil {
		return fmt.Errorf("could not read the host back: %w", err)
	}
	want := r.Repository + ":" + r.ToTag
	script := verifyScript(r.Repository)
	last := "nothing could be read back from the host"
	for polls := 0; ; polls++ {
		out, _, failed := e.run.RunScript(ctx, hostexec.Privileged(script), h)
		if !failed && strings.Contains(out, "::OK::") {
			var waiting []string
			for _, c := range parseVerifyOutput(out) {
				if c.ref != want {
					continue
				}
				if !c.isRunning() {
					return fmt.Errorf("updated to %s, but %s then stopped (%s) while it was still "+
						"starting up. The rest of this host's images were not applied, so nothing "+
						"else was changed underneath it", want, c.name, c.state)
				}
				switch c.health {
				case "unhealthy":
					return fmt.Errorf("updated to %s, but %s reports unhealthy. The rest of this "+
						"host's images were not applied, so nothing else was changed underneath it. "+
						"If it is still migrating it may recover on its own; resume the rollout once "+
						"it reports healthy", want, c.name)
				case "starting":
					waiting = append(waiting, c.name)
				}
			}
			if len(waiting) == 0 {
				return nil
			}
			last = strings.Join(waiting, ", ") + " still starting"
		}
		if time.Duration(polls+1)*settleInterval >= SettleTimeout {
			return fmt.Errorf("updated to %s, but it had not finished starting after %s (%s). "+
				"The rest of this host's images were not applied, so nothing else was changed "+
				"underneath it", want, SettleTimeout, last)
		}
		if err := e.sleep(ctx, settleInterval); err != nil {
			return err
		}
	}
}

// sleepCtx is time.Sleep that gives up when the context does.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
