package scheduler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/notify"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// vulnDBRefreshTimeout bounds one refresh of the CVE databases. A grype database is
// hundreds of megabytes and is unpacked after it lands.
const vulnDBRefreshTimeout = 20 * time.Minute

// vulnDBRefresh returns the work of a CVE-database refresh, to be started once the
// firing is recorded.
//
// A refresh creates no run record, so until this reported back the schedule read
// "started" for ever whether the download worked or not -- and every scan after a
// failed one quietly matched against old data. The result now goes onto the
// firing itself: "completed", or "failed: <why>", and a failure notifies.
//
// ctx is the firing's, without its cancellation: a manual run's request ends long
// before the download does, but the tenant scope it carries must not be lost with
// it (a bare context.Background() has none, and row security refuses the write).
func (e *Engine) vulnDBRefresh(ctx context.Context, sc *models.Schedule) func(time.Time) {
	base := context.WithoutCancel(ctx)
	return func(firedAt time.Time) {
		go func() {
			rctx, cancel := context.WithTimeout(base, vulnDBRefreshTimeout)
			defer cancel()
			var problems []string
			if _, err := e.vuln.DBUpdate(rctx); err != nil {
				e.log.Warn("scheduled vulndb: grype update", "err", err)
				problems = append(problems, "grype database: "+err.Error())
			} else {
				e.log.Info("scheduled vulndb: grype DB updated")
			}
			if e.msrc != nil {
				if n, err := e.msrc.UpdateOnline(rctx); err != nil {
					e.log.Warn("scheduled vulndb: msrc update", "err", err)
					problems = append(problems, "Windows (MSRC) mapping: "+err.Error())
				} else {
					e.log.Info("scheduled vulndb: msrc updated", "entries", n)
				}
			}
			result := "completed"
			if len(problems) > 0 {
				result = trunc("failed: "+strings.Join(problems, "; "), 480)
				e.notifyFailure(base, sc, fmt.Sprintf("CVE database refresh failed (%s)", sc.Name),
					"The scheduled refresh of the CVE databases failed, so vulnerability scans will "+
						"keep matching against the previous data until one succeeds.\n\n"+strings.Join(problems, "\n"))
			}
			e.recordResult(base, sc, firedAt, result)
		}()
	}
}

// reportWhenDone returns the work of watching a batch of scans the firing launched,
// to be started once the firing is recorded. When every scan has finished it
// notifies if any host failed -- including a scan whose record has since gone, which
// is how a failed scan used to vanish: clearing the failures list deleted the only
// evidence, and the schedule still read "started".
func (e *Engine) reportWhenDone(ctx context.Context, sc *models.Schedule, kind string, ids []uuid.UUID, wait func()) func(time.Time) {
	if wait == nil || len(ids) == 0 {
		return nil
	}
	base := context.WithoutCancel(ctx)
	return func(time.Time) {
		go func() {
			wait()
			failures, missing, err := e.store.FailedScheduledRuns(base, kind, ids)
			if err != nil {
				e.log.Warn("scheduler: reading batch outcome", "schedule", sc.ID, "err", err)
				return
			}
			if len(failures) == 0 && missing == 0 {
				return
			}
			title, body := batchFailureMessage(sc, kind, len(ids), failures, missing)
			e.log.Warn("scheduled batch had failures", "schedule", sc.Name,
				"failed", len(failures), "missing", missing, "of", len(ids))
			e.notifyFailure(base, sc, title, body)
		}()
	}
}

// batchFailureMessage words a batch's failures for a person: how many of how many,
// then each host and its reason.
func batchFailureMessage(sc *models.Schedule, kind string, total int, failures []store.ScheduledRunFailure, missing int) (string, string) {
	what := "Security scan"
	if kind == "vulnscan" {
		what = "Vulnerability scan"
	}
	bad := len(failures) + missing
	title := fmt.Sprintf("%s: %d of %d hosts failed (%s)", what, bad, total, sc.Name)
	var b strings.Builder
	fmt.Fprintf(&b, "The scheduled %s \"%s\" finished with %d of %d hosts not assessed.\n\n",
		strings.ToLower(what), sc.Name, bad, total)
	for _, f := range failures {
		fmt.Fprintf(&b, "%s: %s\n", f.Host, f.Error)
	}
	if missing > 0 {
		fmt.Fprintf(&b, "%d scan record(s) from this run no longer exist; a failure that was cleared "+
			"from the failures list is the usual reason.\n", missing)
	}
	return title, b.String()
}

func (e *Engine) notifyFailure(ctx context.Context, sc *models.Schedule, title, body string) {
	if e.nfy == nil {
		return
	}
	e.nfy.Notify(ctx, notify.Event{
		Type:      notify.EventScheduleFailed,
		Severity:  notify.SeverityError,
		Title:     title,
		Body:      body,
		DedupeKey: "schedule:" + sc.ID.String(),
	})
}

func (e *Engine) recordResult(ctx context.Context, sc *models.Schedule, firedAt time.Time, result string) {
	matched, err := e.store.RecordScheduleResult(ctx, sc.ID, firedAt, result)
	switch {
	case err != nil:
		e.log.Warn("scheduler: recording result", "schedule", sc.ID, "err", err)
	case !matched:
		// A later firing has replaced this one on the row; its own result will land.
		e.log.Info("scheduler: result for a superseded firing not recorded", "schedule", sc.Name, "result", result)
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
