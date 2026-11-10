package event

import (
	"context"
	"strings"
	"testing"

	"github.com/cheeseandcereal/proton-cal/pkg/internal/papitest"
)

// The calendar policy addresses events through an allowed calendar; an event
// the server reports as belonging to another calendar must not be used.
func TestGetRejectsEventFromAnotherCalendar(t *testing.T) {
	api := papitest.Fake{Bodies: map[string]string{
		"/calendar/v1/cal-allowed/events/ev1": `{"Event":{"ID":"ev1","CalendarID":"cal-hidden","UID":"u1"}}`,
	}}
	_, err := Get(context.Background(), api, "cal-allowed", "ev1")
	if err == nil || !strings.Contains(err.Error(), "cal-hidden") {
		t.Fatalf("want an error naming the other calendar, got %v", err)
	}
}

func TestGetAcceptsEventFromRequestedCalendar(t *testing.T) {
	api := papitest.Fake{Bodies: map[string]string{
		"/calendar/v1/cal-allowed/events/ev1": `{"Event":{"ID":"ev1","CalendarID":"cal-allowed","UID":"u1"}}`,
	}}
	raw, err := Get(context.Background(), api, "cal-allowed", "ev1")
	if err != nil {
		t.Fatal(err)
	}
	if raw.ID != "ev1" {
		t.Fatalf("ID = %q", raw.ID)
	}
}
