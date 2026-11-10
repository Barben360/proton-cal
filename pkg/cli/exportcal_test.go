package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cheeseandcereal/proton-cal/pkg/calendar"
	"github.com/cheeseandcereal/proton-cal/pkg/calsvc"
)

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

func TestWriteExportsStableNamesAndPrivateFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "export") // created on demand
	exps := []calsvc.CalendarExport{
		{Calendar: calendar.Info{ID: "id-1", Name: "Personal"}, ICS: "BEGIN:VCALENDAR\r\nA\r\nEND:VCALENDAR"},
		{Calendar: calendar.Info{ID: "id-2", Name: "Work / Été 2026"}, ICS: "BEGIN:VCALENDAR\r\nB\r\nEND:VCALENDAR"},
	}
	files, err := writeExports(dir, exps)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %v", files)
	}
	for i, f := range files {
		if filepath.Dir(f) != dir || !strings.HasSuffix(f, ".ics") {
			t.Errorf("bad path %q", f)
		}
		base := filepath.Base(f)
		if strings.ContainsAny(base, " /\\") {
			t.Errorf("unsafe file name %q", base)
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != exps[i].ICS {
			t.Errorf("%s content = %q", base, data)
		}
		st, _ := os.Stat(f)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", base, st.Mode().Perm())
		}
	}
	if !strings.HasPrefix(filepath.Base(files[0]), "personal-") {
		t.Errorf("name should start with the calendar slug: %s", files[0])
	}

	// A pre-existing, wider-mode file is tightened on rewrite.
	if err := os.Chmod(files[0], 0o644); err != nil {
		t.Fatal(err)
	}

	// Same calendars again: same file names (restic dedups), nothing else left.
	before := listDir(t, dir)
	files2, err := writeExports(dir, exps)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(files, files2) || !slices.Equal(before, listDir(t, dir)) {
		t.Fatalf("names changed between runs or stray files: %v vs %v", before, listDir(t, dir))
	}
	if st, _ := os.Stat(files[0]); st.Mode().Perm() != 0o600 {
		t.Errorf("rewritten file mode = %v, want 0600", st.Mode().Perm())
	}
}

func TestWriteExportsSameNameDifferentCalendars(t *testing.T) {
	exps := []calsvc.CalendarExport{
		{Calendar: calendar.Info{ID: "id-1", Name: "Family"}, ICS: "1"},
		{Calendar: calendar.Info{ID: "id-2", Name: "Family"}, ICS: "2"},
	}
	files, err := writeExports(t.TempDir(), exps)
	if err != nil {
		t.Fatal(err)
	}
	if files[0] == files[1] {
		t.Fatalf("two calendars written to the same file %s", files[0])
	}
}

func TestCLIExportValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no selection", []string{"export", "calendar", "--dir", t.TempDir()}, "--all-calendars"},
		{"no dir", []string{"export", "calendar", "--all-calendars"}, "--dir"},
		{"both", []string{"export", "calendar", "Work", "--all-calendars", "--dir", t.TempDir()}, "--all-calendars"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := runCLI(t, detachedFactory, tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("args %v: want error containing %q, got %v", tt.args, tt.want, err)
			}
		})
	}
}

func TestExportReportFailsOnSkippedRows(t *testing.T) {
	exps := []calsvc.CalendarExport{
		{Calendar: calendar.Info{ID: "id-1", Name: "Personal"}, Rows: 10, Skipped: 0},
		{Calendar: calendar.Info{ID: "id-2", Name: "Work"}, Rows: 5, Skipped: 2},
	}
	err := exportOutcome(exps)
	if err == nil || !strings.Contains(err.Error(), "Work") || !strings.Contains(err.Error(), "2") {
		t.Fatalf("want an error naming Work and its 2 skipped rows, got %v", err)
	}
	if err := exportOutcome(exps[:1]); err != nil {
		t.Fatalf("clean export reported as failed: %v", err)
	}
}
