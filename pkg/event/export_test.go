package event

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/cheeseandcereal/proton-cal/pkg/caltypes"
)

// pagingFake serves GET /calendar/v1/{cal}/events one page at a time and
// records the queries it saw.
type pagingFake struct {
	pages   []string // JSON body per Page index
	tail    string   // body past the last page ("" = empty, no cursor)
	queries []url.Values
}

func (f *pagingFake) Get(_ context.Context, path string, q url.Values, out any) error {
	if path != "/calendar/v1/cal1/events" {
		return fmt.Errorf("unexpected path %s", path)
	}
	f.queries = append(f.queries, q)
	page, _ := strconv.Atoi(q.Get("Page"))
	body := `{"Events":[]}`
	if f.tail != "" {
		body = f.tail
	}
	if page < len(f.pages) {
		body = f.pages[page]
	}
	return json.Unmarshal([]byte(body), out)
}
func (*pagingFake) Put(context.Context, string, any, any) error  { return nil }
func (*pagingFake) Post(context.Context, string, any, any) error { return nil }
func (*pagingFake) Delete(context.Context, string, any) error    { return nil }

func eventsPage(from, n int, extra string) string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf(`{"ID":"ev%d","UID":"u%d","CalendarID":"cal1"}`, from+i, from+i)
	}
	return `{"Events":[` + strings.Join(ids, ",") + `]` + extra + `}`
}

func TestListAllFollowsMoreCursor(t *testing.T) {
	f := &pagingFake{pages: []string{eventsPage(0, 100, `,"More":1`), eventsPage(100, 30, `,"More":0`)}}
	rows, err := ListAll(context.Background(), f, "cal1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 130 {
		t.Fatalf("rows = %d, want 130", len(rows))
	}
	for _, q := range f.queries {
		if q.Has("Type") || q.Has("Start") || q.Has("End") {
			t.Fatalf("whole-calendar listing must not be windowed: %v", q)
		}
	}
}

func TestListAllFollowsLegacyTotal(t *testing.T) {
	// The unscoped query carries Total instead of More.
	f := &pagingFake{pages: []string{eventsPage(0, 100, `,"Total":150`), eventsPage(100, 50, `,"Total":150`)}}
	rows, err := ListAll(context.Background(), f, "cal1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 150 {
		t.Fatalf("rows = %d, want 150", len(rows))
	}
}

func TestListAllDeduplicatesAndStopsOnEmptyPage(t *testing.T) {
	// Total claims more than exists; an empty page must end the loop, and a
	// row repeated across pages is kept once.
	f := &pagingFake{
		pages: []string{eventsPage(0, 100, `,"Total":99999999`), eventsPage(99, 10, `,"Total":99999999`)},
		tail:  `{"Events":[],"Total":99999999}`,
	}
	rows, err := ListAll(context.Background(), f, "cal1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 109 {
		t.Fatalf("rows = %d, want 109 (ev99 deduplicated)", len(rows))
	}
}

func TestBuildCalendarICSHoldsEveryEvent(t *testing.T) {
	calKR, _ := testKeys(t)
	single := fabricateRaw(t, "s1", "uidA", 1000, 2000, "UTC", "", 0, nil, "Dentist", 0)
	master := fabricateRaw(t, "m1", "uidS", 1000, 2000, "UTC", "FREQ=WEEKLY", 0, nil, "Weekly", 0)
	ex := fabricateRaw(t, "e1", "uidS", 1000, 2000, "UTC", "", 1_700_000_000, nil, "Weekly edited", 1)
	other := fabricateRaw(t, "s2", "uidB", 1000, 2000, "UTC", "", 0, nil, "Lunch", 0)

	ics, skipped, err := BuildCalendarICS("My \"cal\", 1", []*caltypes.RawEvent{ex, single, other, master}, calKR, nil)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}
	if strings.Count(ics, "BEGIN:VCALENDAR") != 1 || strings.Count(ics, "END:VCALENDAR") != 1 {
		t.Fatalf("want exactly one VCALENDAR:\n%s", ics)
	}
	if n := strings.Count(ics, "BEGIN:VEVENT"); n != 4 {
		t.Fatalf("VEVENT count = %d, want 4\n%s", n, ics)
	}
	for _, s := range []string{"SUMMARY:Dentist", "SUMMARY:Lunch", "RRULE:FREQ=WEEKLY", "SUMMARY:Weekly edited"} {
		if !strings.Contains(ics, s) {
			t.Errorf("missing %q", s)
		}
	}
	// A series' master precedes its exception.
	if strings.Index(ics, "RRULE:FREQ=WEEKLY") > strings.Index(ics, "RECURRENCE-ID") {
		t.Error("exception exported before its master")
	}
	if !strings.Contains(ics, `X-WR-CALNAME:My "cal"\, 1`) {
		t.Errorf("calendar name missing or unescaped:\n%s", ics[:200])
	}
}

func TestBuildCalendarICSIsDeterministic(t *testing.T) {
	calKR, _ := testKeys(t)
	a := fabricateRaw(t, "s1", "uidA", 1000, 2000, "UTC", "", 0, nil, "A", 0)
	b := fabricateRaw(t, "s2", "uidB", 1000, 2000, "UTC", "", 0, nil, "B", 0)
	ics1, _, err1 := BuildCalendarICS("c", []*caltypes.RawEvent{a, b}, calKR, nil)
	ics2, _, err2 := BuildCalendarICS("c", []*caltypes.RawEvent{b, a}, calKR, nil)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if ics1 != ics2 {
		t.Error("export depends on row order (backups would churn)")
	}
}

func TestBuildCalendarICSCountsUndecryptableRows(t *testing.T) {
	calKR, _ := testKeys(t)
	good := fabricateRaw(t, "s1", "uidA", 1000, 2000, "UTC", "", 0, nil, "Good", 0)
	bad := fabricateRaw(t, "s2", "uidB", 1000, 2000, "UTC", "", 0, nil, "Bad", 0)
	bad.SharedEvents, bad.CalendarEvents, bad.AttendeesEvents = nil, nil, nil

	ics, skipped, err := BuildCalendarICS("c", []*caltypes.RawEvent{good, bad}, calKR, nil)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}
	if !strings.Contains(ics, "SUMMARY:Good") || strings.Count(ics, "BEGIN:VEVENT") != 1 {
		t.Errorf("want only the good event:\n%s", ics)
	}
}

func TestBuildCalendarICSEmptyCalendarIsValid(t *testing.T) {
	ics, skipped, err := BuildCalendarICS("Empty", nil, nil, nil)
	if err != nil || skipped != 0 {
		t.Fatalf("err=%v skipped=%d", err, skipped)
	}
	if !strings.HasPrefix(ics, "BEGIN:VCALENDAR") || !strings.HasSuffix(ics, "END:VCALENDAR") || strings.Contains(ics, "BEGIN:VEVENT") {
		t.Fatalf("bad empty export:\n%s", ics)
	}
}

func TestBuildCalendarICSAllUndecryptableFails(t *testing.T) {
	bad := fabricateRaw(t, "s2", "uidB", 1000, 2000, "UTC", "", 0, nil, "Bad", 0)
	bad.SharedEvents, bad.CalendarEvents, bad.AttendeesEvents = nil, nil, nil
	if _, _, err := BuildCalendarICS("c", []*caltypes.RawEvent{bad}, nil, nil); !errors.Is(err, ErrDecryptDegraded) {
		t.Fatalf("err = %v, want ErrDecryptDegraded", err)
	}
}
