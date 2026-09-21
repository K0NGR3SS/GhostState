package report

import (
	"os"
	"time"
)

const CostNote = "Monthly costs and savings are estimates based on known resource shape and static pricing hints."

// CreateTemp uses exclusive creation and owner-only permissions. Rapid exports
// must never truncate an earlier report or the currently active auto-save file.
func newReportFile(extension string) (*os.File, error) {
	return os.CreateTemp(".", "ghoststate_report_"+time.Now().Format("2006-01-02_150405")+"_*."+extension)
}

// finishReport exposes close failures and removes incomplete manual exports.
func finishReport(file *os.File, filename *string, err *error) {
	if closeErr := file.Close(); *err == nil {
		*err = closeErr
	}
	if *err != nil {
		_ = os.Remove(file.Name())
		*filename = ""
	}
}
