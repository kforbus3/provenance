package containerupdate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kforbus3/provenance/backend/internal/hostexec"
	"github.com/kforbus3/provenance/backend/internal/notify"
)

// The post-rollout watch.
//
// A rollout stops looking at a host the moment it is verified, and the soak
// re-check only ever asks whether the canary is still running, not unhealthy and
// not restarted. On 2026-10-04 a speech-to-text image passed all of that and then
// failed every request it was given: the new build carried a library that had
// dropped an argument the application still passed. The traceback reached the
// log only when the first real request arrived, three hours after the rollout
// had completed, and the healthcheck -- a port probe -- went on answering. Every
// dashboard said healthy. The person who found it was the person whose voice
// assistant had stopped answering.
//
// So every container a rollout updates is watched for WatchWindow afterwards:
// its logs are read from a cursor every WatchEvery, and the first error trace
// (see logTracePattern) is recorded on the rollout and raised as
// container.rollout.regression. Once per container: the point is to be told,
// not to be told every ten minutes.
const (
	WatchWindow = 24 * time.Hour
	WatchEvery  = 10 * time.Minute
)

// watch reads the logs of every watched container whose turn has come.
func (e *Engine) watch(ctx context.Context) {
	now := e.now()
	due, err := e.store.DueRolloutWatches(ctx, now, WatchEvery)
	if err != nil {
		e.log.Warn("update rollout watch: listing", "err", err)
		return
	}
	for _, w := range due {
		if ctx.Err() != nil {
			return
		}
		host, err := e.store.GetHost(ctx, w.HostID)
		if err != nil {
			e.log.Warn("update rollout watch: could not read host", "host", w.HostID, "err", err)
			continue
		}
		since := w.CheckedAt.UTC().Format(time.RFC3339)
		out, _, failed := e.run.RunScript(ctx, hostexec.Privileged(verifyScriptSince(w.Repository, since)), host)
		if failed || !strings.Contains(out, "::OK::") {
			// The cursor stays where it is: the logs it points at have not been
			// read, and moving it would be deciding they were clean. The host is
			// tried again next tick; a host that is down is the monitor's to report.
			e.log.Info("update rollout watch: could not read the host", "host", host.Hostname,
				"repository", w.Repository, "detail", trimOutput(out))
			continue
		}
		want := w.Repository + ":" + w.ToTag
		regression := ""
		for _, c := range parseVerifyOutput(out) {
			if c.ref != want || c.traces <= 0 {
				continue
			}
			regression = fmt.Sprintf("container %s on %s has logged %d error trace(s) since %s; the first: %s",
				c.name, host.Hostname, c.traces, w.CheckedAt.Local().Format("15:04 Jan 2"), c.trace)
			break
		}
		if err := e.store.SetRolloutWatchChecked(ctx, w.ID, now, regression); err != nil {
			e.log.Warn("update rollout watch: recording", "watch", w.ID, "err", err)
			continue
		}
		if regression == "" {
			continue
		}
		e.log.Warn("update rollout watch: regression after rollout", "rollout", w.RolloutID,
			"host", host.Hostname, "image", want, "detail", regression)
		if e.nfy != nil {
			e.nfy.Notify(context.WithoutCancel(ctx), notify.Event{
				Type:      notify.EventContainerRolloutRegression,
				Severity:  notify.SeverityWarning,
				Title:     fmt.Sprintf("Container update regression: %s on %s", want, host.Hostname),
				Body:      regression + "\n\nThe container is running and passing its healthcheck, which is why nothing else has noticed. Check its logs, and pin the image back to its previous tag if the trace is the update's doing.",
				DedupeKey: "rollout-watch:" + w.ID.String(),
			})
		}
	}
}
