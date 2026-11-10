//go:build integration

package calsvc

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestE2EExportCalendar exports the test calendar after creating a single
// event and a weekly series with one edited occurrence, and checks that every
// one of them is in the .ics (fork addition).
func TestE2EExportCalendar(t *testing.T) {
	svc, cal := liveService(t)
	ctx := context.Background()
	start, end := e2eFutureSlot()

	single := e2eSummary("export single")
	ev, err := svc.CreateEvent(ctx, CreateEventInput{Summary: single, Start: start, End: end, Calendar: cal})
	if err != nil {
		t.Fatal(err)
	}
	trackDelete(t, svc, cal, ev.ID)

	series := e2eSummary("export series")
	sev, err := svc.CreateEvent(ctx, CreateEventInput{Summary: series, Start: start, End: end, Calendar: cal, Recurrence: Recurrence{Repeat: "weekly", Count: 3}})
	if err != nil {
		t.Fatal(err)
	}
	trackDelete(t, svc, cal, sev.ID)
	day := strings.Fields(start)[0]
	d, _ := time.Parse("2006-01-02", day)
	edited := e2eSummary("export edited occurrence")
	if _, err := svc.UpdateEvent(ctx, UpdateEventInput{EventID: sev.ID, Occurrence: d.AddDate(0, 0, 7).Format("2006-01-02") + " 09:00", Summary: &edited, Calendar: cal}); err != nil {
		t.Fatalf("editing one occurrence: %v", err)
	}

	exps, err := svc.ExportCalendars(ctx, []string{cal}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(exps) != 1 {
		t.Fatalf("exports = %d, want 1", len(exps))
	}
	ics := exps[0].ICS
	if exps[0].Skipped != 0 {
		t.Errorf("skipped %d rows", exps[0].Skipped)
	}
	for _, s := range []string{single, series, edited} {
		if !strings.Contains(ics, "SUMMARY:"+s) {
			t.Errorf("export lacks %q", s)
		}
	}
	if !strings.Contains(ics, "RRULE:") || !strings.Contains(ics, "RECURRENCE-ID") {
		t.Error("export lacks the series master or its edited occurrence")
	}
}
