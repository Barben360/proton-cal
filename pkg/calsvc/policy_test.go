package calsvc

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cheeseandcereal/proton-cal/pkg/calendar"
	"github.com/cheeseandcereal/proton-cal/pkg/config"
)

// Fixture: Personal (account default), Work, Shared (someone else's), Agent.
func policyFixture(t *testing.T, defaultID string) *fakeRawAPI {
	t.Helper()
	return &fakeRawAPI{bodies: map[string]string{
		calendar.APIPath: calListBody(t,
			[2]string{"id-personal", "Personal"},
			[2]string{"id-work", "Work"},
			[2]string{"id-shared", "Shared"},
			[2]string{"id-agent", "Agent"},
		),
		calendar.UserSettingsPath: userSettingsBody(defaultID),
	}}
}

// Read: Personal + Work (Work by ID); write: Personal + Agent. Shared is hidden.
var restricted = config.Config{
	Timezone:       "UTC",
	ReadCalendars:  []string{"Personal", "id-work"},
	WriteCalendars: []string{"personal", "Agent"},
}

func names(cals []calendar.Info) []string {
	out := make([]string, len(cals))
	for i, c := range cals {
		out[i] = c.Name
	}
	slices.Sort(out)
	return out
}

func TestPolicyMatrix(t *testing.T) {
	p := policyFrom(restricted)
	cases := []struct {
		cal             calendar.Info
		readable, write bool
	}{
		{calendar.Info{ID: "id-personal", Name: "Personal"}, true, true},
		{calendar.Info{ID: "id-work", Name: "Work"}, true, false},         // read list, by ID
		{calendar.Info{ID: "id-agent", Name: "Agent"}, true, true},        // write implies read
		{calendar.Info{ID: "id-shared", Name: "Shared"}, false, false},    // in neither list
		{calendar.Info{ID: "id-x", Name: "PERSONAL"}, true, true},         // names match case-insensitively
		{calendar.Info{ID: "id-y", Name: "Personal (old)"}, false, false}, // no substring match
	}
	for _, c := range cases {
		if got := p.readable(c.cal); got != c.readable {
			t.Errorf("readable(%s/%s) = %v, want %v", c.cal.ID, c.cal.Name, got, c.readable)
		}
		if got := p.writable(c.cal); got != c.write {
			t.Errorf("writable(%s/%s) = %v, want %v", c.cal.ID, c.cal.Name, got, c.write)
		}
	}
}

func TestPolicyUnsetAllowsEverything(t *testing.T) {
	p := policyFrom(config.Config{})
	c := calendar.Info{ID: "id", Name: "Anything"}
	if !p.readable(c) || !p.writable(c) {
		t.Fatal("no policy must allow reading and writing every calendar")
	}
}

func TestPolicyReadOnlyListMakesWritesFollowReads(t *testing.T) {
	// write_calendars unset: every readable calendar is writable, the rest are not.
	p := policyFrom(config.Config{ReadCalendars: []string{"Work"}})
	if !p.writable(calendar.Info{ID: "a", Name: "Work"}) {
		t.Error("readable calendar must be writable when write_calendars is unset")
	}
	if p.writable(calendar.Info{ID: "b", Name: "Shared"}) {
		t.Error("hidden calendar must not be writable")
	}
}

func TestCalendarsHidesUnreadable(t *testing.T) {
	s := detachedWithAPI(restricted, policyFixture(t, "id-personal"))
	cals, err := s.Calendars(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := names(cals), []string{"Agent", "Personal", "Work"}; !slices.Equal(got, want) {
		t.Fatalf("Calendars = %v, want %v", got, want)
	}
}

func TestHiddenCalendarCannotBeResolved(t *testing.T) {
	s := detachedWithAPI(restricted, policyFixture(t, "id-personal"))
	for _, sel := range []string{"Shared", "id-shared"} {
		if info, err := s.ResolveCalendarInfo(context.Background(), sel); err == nil {
			t.Errorf("hidden calendar resolved via %q: %+v", sel, info)
		}
	}
}

func TestListAllCalendarsSkipsHidden(t *testing.T) {
	s := detachedWithAPI(restricted, policyFixture(t, "id-personal"))
	cals, err := s.resolveCalendars(context.Background(), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(cals); slices.Contains(got, "Shared") {
		t.Fatalf("all_calendars includes hidden calendar: %v", got)
	}
	if _, err := s.resolveCalendars(context.Background(), []string{"Work", "Shared"}, false); err == nil {
		t.Fatal("explicit hidden calendar accepted in a multi-calendar list")
	}
}

func TestHiddenDefaultIsNotUsedForReads(t *testing.T) {
	// The account default is the hidden Shared calendar: an unspecified read
	// must not land on it.
	s := detachedWithAPI(restricted, policyFixture(t, "id-shared"))
	info, err := s.ResolveCalendarInfo(context.Background(), "")
	if err == nil && info.ID == "id-shared" {
		t.Fatal("unspecified selector resolved to the hidden default calendar")
	}
}

// Every write must be refused before any key unlock: the detached service has
// no client, so reaching the unlock would panic instead of returning.
func TestWritesToReadOnlyCalendarAreRefused(t *testing.T) {
	ctx := context.Background()
	writes := map[string]func(s *Service) error{
		"create_event": func(s *Service) error {
			_, err := s.CreateEvent(ctx, CreateEventInput{Summary: "x", Start: "2026-12-01 09:00", End: "2026-12-01 10:00", Calendar: "Work"})
			return err
		},
		"update_event": func(s *Service) error {
			y := "y"
			_, err := s.UpdateEvent(ctx, UpdateEventInput{EventID: "ev", Summary: &y, Calendar: "Work"})
			return err
		},
		"delete_event": func(s *Service) error {
			_, err := s.DeleteEvent(ctx, DeleteEventInput{EventID: "ev", Calendar: "Work"})
			return err
		},
		"update_calendar": func(s *Service) error {
			n := "Renamed"
			_, err := s.UpdateCalendar(ctx, UpdateCalendarInput{Selector: "Work", Name: &n})
			return err
		},
		"delete_calendar": func(s *Service) error {
			return s.DeleteCalendar(ctx, DeleteCalendarInput{Selector: "Work", Password: "pw"})
		},
		"create_calendar": func(s *Service) error {
			_, err := s.CreateCalendar(ctx, CreateCalendarInput{Name: "Brand new"})
			return err
		},
	}
	for name, write := range writes {
		t.Run(name, func(t *testing.T) {
			s := detachedWithAPI(restricted, policyFixture(t, "id-personal"))
			err := write(s)
			if !errors.Is(err, ErrNotWritable) {
				t.Fatalf("want ErrNotWritable, got %v", err)
			}
		})
	}
}

func TestWriteToHiddenCalendarIsRefused(t *testing.T) {
	s := detachedWithAPI(restricted, policyFixture(t, "id-personal"))
	_, err := s.DeleteEvent(context.Background(), DeleteEventInput{EventID: "ev", Calendar: "Shared"})
	if err == nil {
		t.Fatal("write to a hidden calendar accepted")
	}
}

func TestUnspecifiedWriteWithReadOnlyDefaultIsRefused(t *testing.T) {
	// Default = Work (readable, not writable). No calendar given: refuse and
	// name the writable calendars instead of silently picking another one.
	s := detachedWithAPI(restricted, policyFixture(t, "id-work"))
	_, err := s.CreateEvent(context.Background(), CreateEventInput{Summary: "x", Start: "2026-12-01 09:00", End: "2026-12-01 10:00"})
	if !errors.Is(err, ErrNotWritable) {
		t.Fatalf("want ErrNotWritable, got %v", err)
	}
	for _, want := range []string{"Personal", "Agent"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not list writable calendar %q: %v", want, err)
		}
	}
}

func TestCreateCalendarAllowedOnlyForListedName(t *testing.T) {
	p := policyFrom(restricted)
	if !p.mayCreate("Agent") {
		t.Error("creating a calendar named in write_calendars must be allowed")
	}
	if p.mayCreate("Other") {
		t.Error("creating an unlisted calendar must be refused")
	}
	if !policyFrom(config.Config{}).mayCreate("Other") {
		t.Error("no policy must allow creating any calendar")
	}
}
