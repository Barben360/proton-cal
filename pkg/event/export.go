package event

// Whole-calendar export (fork addition): every row of a calendar, rebuilt as
// one VCALENDAR, for backups.

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"

	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/cheeseandcereal/proton-cal/pkg/calendar"
	"github.com/cheeseandcereal/proton-cal/pkg/caltypes"
	"github.com/cheeseandcereal/proton-cal/pkg/ical"
)

// maxExportPages bounds the unscoped paging loop (100 rows a page), so a
// misbehaving cursor cannot spin forever.
const maxExportPages = 10_000

// ListAll returns every raw row of a calendar: the unscoped /events query (no
// Type, so no window), paged until More/Total say it is done or a page comes
// back empty. Rows are deduplicated by ID.
func ListAll(ctx context.Context, client calendarGetter, calendarID string) ([]*caltypes.RawEvent, error) {
	var all []*caltypes.RawEvent
	seen := map[string]bool{}
	for page := range maxExportPages {
		q := url.Values{}
		q.Set("Page", strconv.Itoa(page))
		q.Set("PageSize", strconv.Itoa(pageSize))
		var resp eventsResponse
		if err := client.Get(ctx, calendar.APIPath+"/"+calendarID+"/events", q, &resp); err != nil {
			return nil, fmt.Errorf("calendar %s: listing all events: %w", calendarID, err)
		}
		for _, ev := range resp.Events {
			if ev == nil || seen[ev.ID] {
				continue
			}
			seen[ev.ID] = true
			all = append(all, ev)
		}
		fetched := (page + 1) * pageSize
		more := resp.More == 1 || (resp.Total > 0 && fetched < resp.Total)
		if len(resp.Events) == 0 || !more {
			return all, nil
		}
	}
	return nil, fmt.Errorf("calendar %s: listing all events: more than %d pages", calendarID, maxExportPages)
}

// calendarGetter is the read half of papi.API.
type calendarGetter interface {
	Get(ctx context.Context, path string, query url.Values, out any) error
}

// BuildCalendarICS rebuilds one VCALENDAR (named calName via X-WR-CALNAME)
// holding every row: series grouped by UID, master first, groups ordered by
// first start then UID so the output does not depend on API order. Rows that
// cannot be decrypted are skipped and counted; an empty calendar is a valid
// empty VCALENDAR, but rows none of which decrypt is ErrDecryptDegraded.
func BuildCalendarICS(calName string, rows []*caltypes.RawEvent, calKR *crypto.KeyRing, extrasByID map[string]RowExtras) (ics string, skipped int, err error) {
	groups := map[string][]*caltypes.RawEvent{}
	for _, r := range rows {
		if r == nil {
			continue
		}
		key := r.UID
		if key == "" {
			key = "id:" + r.ID
		}
		groups[key] = append(groups[key], r)
	}
	type group struct {
		key   string
		start int64
		rows  []*caltypes.RawEvent
	}
	ordered := make([]group, 0, len(groups))
	for k, g := range groups {
		start := g[0].StartTime
		for _, r := range g[1:] {
			start = min(start, r.StartTime)
		}
		ordered = append(ordered, group{k, start, orderSeriesRows(g)})
	}
	slices.SortFunc(ordered, func(a, b group) int {
		return cmp.Or(cmp.Compare(a.start, b.start), cmp.Compare(a.key, b.key))
	})

	bodies := [][]string{{ical.FoldLine("X-WR-CALNAME:" + ical.EscapeText(calName))}}
	built := 0
	for _, g := range ordered {
		for _, raw := range g.rows {
			extras, ok := extrasByID[raw.ID]
			if !ok {
				extras = ExtrasFromRow(raw)
			}
			body, berr := buildVEventBody(raw, calKR, extras)
			if berr != nil {
				skipped++
				continue
			}
			bodies = append(bodies, body)
			built++
		}
	}
	if built == 0 && skipped > 0 {
		return "", skipped, ErrDecryptDegraded
	}
	return ical.MergeVCalendar(ICSProdID, bodies...), skipped, nil
}
