package cli

// `export calendar` (fork addition): whole calendars to .ics files, for
// backups. It ignores read_calendars / write_calendars so a backup is
// complete.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/natefinch/atomic"
	"github.com/spf13/cobra"

	"github.com/cheeseandcereal/proton-cal/pkg/calsvc"
)

func newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export whole calendars as iCalendar (.ics) files",
		Args:  requireArgs(cobra.NoArgs),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errMissingSubcommand
		},
	}
	cmd.AddCommand(newExportCalendarCmd())
	return cmd
}

func newExportCalendarCmd() *cobra.Command {
	var (
		dir string
		all bool
	)
	cmd := &cobra.Command{
		Use:   "calendar [CALENDAR...]",
		Short: "Export calendars (by ID or name, or --all-calendars) to .ics files in --dir",
		Long: "Export every event of the given calendars (or of all calendars with\n" +
			"--all-calendars) into one .ics file per calendar in --dir, named\n" +
			"<name>-<id hash>.ics so names stay stable across runs. Files are written\n" +
			"atomically with mode 0600.\n\n" +
			"For backups: read_calendars / write_calendars are ignored. The command\n" +
			"fails (non-zero exit) when any calendar fails, writing nothing, and also\n" +
			"when any event could not be decrypted (the other events are still written).",
		Args: requireArgs(cobra.ArbitraryArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			if all == (len(args) > 0) {
				return errors.New("name the calendars to export, or pass --all-calendars (not both)")
			}
			if dir == "" {
				return errors.New("--dir is required")
			}
			svc, err := serviceFactory()
			if err != nil {
				return err
			}
			defer svc.Close()

			exps, err := svc.ExportCalendars(cmd.Context(), args, all)
			if err != nil {
				return err
			}
			files, err := writeExports(dir, exps)
			if err != nil {
				return err
			}
			if outputJSON() {
				type row struct {
					CalendarID string `json:"calendar_id"`
					Name       string `json:"name"`
					File       string `json:"file"`
					Rows       int    `json:"rows"`
					Skipped    int    `json:"skipped"`
				}
				out := make([]row, len(exps))
				for i, e := range exps {
					out[i] = row{e.Calendar.ID, e.Calendar.Name, files[i], e.Rows, e.Skipped}
				}
				if err := printJSON(out); err != nil {
					return err
				}
			} else {
				w := humanOut()
				for i, e := range exps {
					fmt.Fprintf(w, "%s: %d event rows -> %s\n", e.Calendar.Name, e.Rows, files[i])
				}
			}
			return exportOutcome(exps)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "directory to write the .ics files into (created if missing)")
	cmd.Flags().BoolVar(&all, "all-calendars", false, "export every calendar on the account")
	return cmd
}

// exportOutcome turns undecryptable rows into an error, so a backup job
// notices a degraded export.
func exportOutcome(exps []calsvc.CalendarExport) error {
	var bad []string
	for _, e := range exps {
		if e.Skipped > 0 {
			bad = append(bad, fmt.Sprintf("%q: %d of %d rows", e.Calendar.Name, e.Skipped, e.Rows))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("some events could not be decrypted and were left out (%s)", strings.Join(bad, "; "))
	}
	return nil
}

// writeExports writes each export atomically (mode 0600) into dir and returns
// the paths, in order.
func writeExports(dir string, exps []calsvc.CalendarExport) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	files := make([]string, len(exps))
	for i, e := range exps {
		p := filepath.Join(dir, exportFileName(e.Calendar.Name, e.Calendar.ID))
		if err := atomic.WriteFile(p, bytes.NewReader([]byte(e.ICS))); err != nil {
			return nil, fmt.Errorf("writing %s: %w", p, err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			return nil, err
		}
		files[i] = p
	}
	return files, nil
}

// exportFileName is "<slug>-<8 hex of sha256(ID)>.ics": readable, filesystem
// safe, stable for a calendar, distinct for two calendars sharing a name.
func exportFileName(name, id string) string {
	sum := sha256.Sum256([]byte(id))
	return slug(name) + "-" + hex.EncodeToString(sum[:4]) + ".ics"
}

func slug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
		if b.Len() >= 40 {
			break
		}
	}
	s := strings.TrimRight(b.String(), "-")
	if s == "" {
		return "calendar"
	}
	return s
}
