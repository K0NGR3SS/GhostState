package aws

import tea "github.com/charmbracelet/bubbletea"

type FoundMsg string
type FinishedMsg struct{}

type AuditMode string

const (
	ModeMissingSpecificTag AuditMode = "MISSING_SPECIFIC_TAG"
	ModeNoTags             AuditMode = "NO_TAGS"
)

type AuditConfig struct {
	ScanEC2       bool
	ScanS3        bool
	ScanRDS       bool
	ScanElasti    bool
	ScanACM       bool
	ScanSecGroups bool
	ScanECS        bool
	ScanCloudfront bool

	Mode      AuditMode
	TargetKey string
	TargetVal string
}

func send(p *tea.Program, s string) {
	if p != nil {
		p.Send(FoundMsg(s))
	}
}
