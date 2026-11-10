package calsvc

// Calendar access policy (fork addition): config.toml's read_calendars and
// write_calendars restrict which calendars this process may see and change,
// for both the CLI and the MCP server.
//
// Rules:
//   - An entry matches a calendar by exact ID or case-insensitive name.
//   - read_calendars unset: every calendar is visible.
//   - write_calendars unset: every visible calendar is writable.
//   - A calendar in write_calendars is also visible.
//   - A hidden calendar cannot be listed or resolved at all; a visible but
//     read-only calendar refuses every write with ErrNotWritable, before any
//     key is unlocked.
//   - With no calendar given, a read never falls back onto a hidden account
//     default, and a write refuses (naming the writable calendars) when the
//     account default is not writable.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cheeseandcereal/proton-cal/pkg/calendar"
	"github.com/cheeseandcereal/proton-cal/pkg/config"
)

// ErrNotWritable marks a write refused by write_calendars.
var ErrNotWritable = errors.New("calendar is read-only for proton-cal (write_calendars)")

type policy struct {
	read, write []string
}

func policyFrom(cfg config.Config) policy {
	return policy{read: cfg.ReadCalendars, write: cfg.WriteCalendars}
}

func matchesAny(entries []string, c calendar.Info) bool {
	for _, e := range entries {
		if e == c.ID || strings.EqualFold(e, c.Name) {
			return true
		}
	}
	return false
}

func (p policy) readable(c calendar.Info) bool {
	return len(p.read) == 0 || matchesAny(p.read, c) || matchesAny(p.write, c)
}

func (p policy) writable(c calendar.Info) bool {
	if len(p.write) == 0 {
		return p.readable(c)
	}
	return matchesAny(p.write, c)
}

// mayCreate reports whether a new calendar with this name may be created: it
// must be writable once it exists, so only names the policy lets us write.
func (p policy) mayCreate(name string) bool {
	return p.writable(calendar.Info{Name: name})
}

func (p policy) visible(cals []calendar.Info) []calendar.Info {
	if len(p.read) == 0 {
		return cals
	}
	out := make([]calendar.Info, 0, len(cals))
	for _, c := range cals {
		if p.readable(c) {
			out = append(out, c)
		}
	}
	return out
}

func (p policy) writableNames(cals []calendar.Info) string {
	var names []string
	for _, c := range cals {
		if p.writable(c) {
			names = append(names, fmt.Sprintf("%q", c.Name))
		}
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

func (s *Service) policy() policy { return policyFrom(s.cfg) }

func (s *Service) notWritable(info calendar.Info) error {
	return fmt.Errorf("calendar %q: %w", info.Name, ErrNotWritable)
}

// resolveWritable resolves a selector for a write and checks write_calendars.
// No selector: the account default must be writable (no silent fallback).
func (s *Service) resolveWritable(ctx context.Context, selector string) (calendar.Info, error) {
	p := s.policy()
	return resolveWith(ctx, s, selector == "",
		func(cals []calendar.Info, defaultID string) (calendar.Info, error) {
			vis := p.visible(cals)
			if selector == "" && defaultID != "" {
				for _, c := range cals {
					if c.ID == defaultID && !p.writable(c) {
						return calendar.Info{}, fmt.Errorf("no calendar given and the account default is not writable; pass calendar (writable: %s): %w",
							p.writableNames(cals), ErrNotWritable)
					}
				}
			}
			info, err := calendar.Resolve(vis, selector, defaultID)
			if err != nil {
				return calendar.Info{}, err
			}
			if !p.writable(info) {
				return calendar.Info{}, s.notWritable(info)
			}
			return info, nil
		})
}

// withWriteAccessResult is withAccessResult for writes: the calendar is
// checked against write_calendars before any key unlock, and again on the
// calendar actually used (a retry may re-resolve the selector).
func withWriteAccessResult[T any](
	ctx context.Context,
	s *Service,
	selector string,
	fn func(info calendar.Info, access *calendar.Access) (*T, bool, error),
) (*T, error) {
	if _, err := s.resolveWritable(ctx, selector); err != nil {
		return nil, err
	}
	return withAccessResult(ctx, s, selector, func(info calendar.Info, access *calendar.Access) (*T, bool, error) {
		if !s.policy().writable(info) {
			return nil, false, s.notWritable(info)
		}
		return fn(info, access)
	})
}
