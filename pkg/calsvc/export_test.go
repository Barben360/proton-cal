package calsvc

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cheeseandcereal/proton-cal/pkg/calendar"
)

func exportedNames(exps []CalendarExport) []string {
	var out []string
	for _, e := range exps {
		out = append(out, e.Calendar.Name)
	}
	slices.Sort(out)
	return out
}

// Backups must be complete: export ignores read_calendars/write_calendars.
func TestExportAllIncludesCalendarsHiddenByPolicy(t *testing.T) {
	s, fake := recoveryService(t)
	s.cfg.ReadCalendars = []string{"Chosen"}
	fake.bodies[calendar.APIPath+"/first/events"] = `{"Events":[]}`
	fake.bodies[calendar.APIPath+"/chosen/events"] = `{"Events":[]}`

	exps, err := s.ExportCalendars(context.Background(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := exportedNames(exps), []string{"Chosen", "First"}; !slices.Equal(got, want) {
		t.Fatalf("exported %v, want %v", got, want)
	}
	for _, e := range exps {
		if !strings.Contains(e.ICS, "X-WR-CALNAME:"+e.Calendar.Name) || !strings.HasPrefix(e.ICS, "BEGIN:VCALENDAR") {
			t.Errorf("%s: bad ICS:\n%s", e.Calendar.Name, e.ICS)
		}
	}
}

func TestExportSelectedCalendarOnly(t *testing.T) {
	s, fake := recoveryService(t)
	fake.bodies[calendar.APIPath+"/first/events"] = `{"Events":[]}`
	exps, err := s.ExportCalendars(context.Background(), []string{"First"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := exportedNames(exps); !slices.Equal(got, []string{"First"}) {
		t.Fatalf("exported %v, want [First]", got)
	}
	if gets := fake.getCounts(); gets[calendar.APIPath+"/chosen/events"] != 0 {
		t.Error("an unselected calendar was fetched")
	}
}

func TestExportRequiresASelection(t *testing.T) {
	s, _ := recoveryService(t)
	if _, err := s.ExportCalendars(context.Background(), nil, false); err == nil {
		t.Fatal("export with neither calendars nor all accepted")
	}
}

func TestExportFailureNamesTheCalendar(t *testing.T) {
	s, fake := recoveryService(t)
	fake.bodies[calendar.APIPath+"/first/events"] = `{"Events":[]}`
	fake.errs[calendar.APIPath+"/chosen/events"] = errors.New("boom")
	_, err := s.ExportCalendars(context.Background(), nil, true)
	if err == nil || !strings.Contains(err.Error(), "Chosen") {
		t.Fatalf("want an error naming calendar Chosen, got %v", err)
	}
}
