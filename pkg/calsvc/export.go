package calsvc

// Whole-calendar .ics export (fork addition), for backups. It deliberately
// ignores read_calendars / write_calendars: a backup must hold every
// calendar. It is a CLI command only, never an MCP tool.

import (
	"context"
	"errors"
	"fmt"

	"github.com/cheeseandcereal/proton-cal/pkg/calendar"
	"github.com/cheeseandcereal/proton-cal/pkg/event"
)

// CalendarExport is one calendar rebuilt as a single VCALENDAR.
type CalendarExport struct {
	Calendar calendar.Info
	ICS      string
	Rows     int // raw rows fetched
	Skipped  int // rows left out because they could not be decrypted
}

// ExportCalendars exports the selected calendars (or every calendar with
// all), one at a time. Any failure fails the whole export: a backup job must
// not mistake a partial run for a good one.
func (s *Service) ExportCalendars(ctx context.Context, selectors []string, all bool) ([]CalendarExport, error) {
	if !all && len(selectors) == 0 {
		return nil, errors.New("name at least one calendar, or export all calendars")
	}
	cals, err := s.resolveCalendarsWith(ctx, policy{}, selectors, all)
	if err != nil {
		return nil, err
	}
	out := make([]CalendarExport, 0, len(cals))
	for _, info := range cals {
		exp, err := s.exportOne(ctx, info)
		if err == nil && exp.Skipped > 0 && s.healCalendarKeys(info.ID) {
			// Undecryptable rows may come from stale cached keys: retry once fresh.
			exp, err = s.exportOne(ctx, info)
		}
		if err != nil {
			return nil, fmt.Errorf("exporting calendar %q: %w", info.Name, err)
		}
		out = append(out, exp)
	}
	return out, nil
}

func (s *Service) exportOne(ctx context.Context, info calendar.Info) (CalendarExport, error) {
	kc, err := s.keychainLazy(ctx)
	if err != nil {
		return CalendarExport{}, err
	}
	access, err := s.unlockCalendar(ctx, info, kc)
	if err != nil {
		return CalendarExport{}, err
	}
	rows, err := event.ListAll(ctx, s.client, info.ID)
	if err != nil {
		return CalendarExport{}, err
	}
	extras := make(map[string]event.RowExtras, len(rows))
	for _, r := range rows {
		if ev, derr := event.Decrypt(r, access.KR); derr == nil && !ev.DecryptFailed {
			extras[r.ID] = s.effectiveExtras(ev, info, access.Settings)
		}
	}
	ics, skipped, err := event.BuildCalendarICS(info.Name, rows, access.KR, extras)
	if err != nil {
		return CalendarExport{}, err
	}
	return CalendarExport{Calendar: info, ICS: ics, Rows: len(rows), Skipped: skipped}, nil
}
