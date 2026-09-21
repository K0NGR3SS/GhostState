package ui

import (
	"context"
	ghostAws "github.com/K0NGR3SS/GhostState/internal/aws"
	tea "github.com/charmbracelet/bubbletea"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

func TestParseRegionListDedupesAndTrims(t *testing.T) {
	got := parseRegionList(" us-east-1, eu-west-1,us-east-1,, ap-southeast-2 ")
	want := []string{"us-east-1", "eu-west-1", "ap-southeast-2"}

	if len(got) != len(want) {
		t.Fatalf("got %d regions, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("region %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFilterResultsQuickFiltersAndSearch(t *testing.T) {
	m := InitialModel()
	items := []scanner.Resource{
		{ID: "sg-open", Service: "Security Group", Risk: "HIGH", RiskInfo: "Open to World"},
		{ID: "vol-unused", Service: "EBS", IsGhost: true, SavingsEstimate: 7.5},
		{ID: "bucket-safe", Service: "S3", Risk: "SAFE", Recommendation: "Enable versioning"},
	}

	m.quickFilter = "SAVINGS"
	got := m.filterResults(items)
	if len(got) != 1 || got[0].ID != "vol-unused" {
		t.Fatalf("savings filter returned %#v", got)
	}

	m.quickFilter = ""
	m.searchFilter = "versioning"
	got = m.filterResults(items)
	if len(got) != 1 || got[0].ID != "bucket-safe" {
		t.Fatalf("recommendation search returned %#v", got)
	}
}

func updateModel(t *testing.T, m Model, msg tea.Msg) (Model, tea.Cmd) {
	t.Helper()
	next, cmd := m.Update(msg)
	return next.(Model), cmd
}

func TestConfigTypingDoesNotTriggerShortcuts(t *testing.T) {
	m := InitialModel()
	m.state = StateConfig
	for _, r := range "ManagedByTerraformJKarm" {
		m, _ = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	if got := m.inputs[0].Value(); got != "ManagedByTerraformJKarm" {
		t.Fatalf("tag input corrupted: %q", got)
	}
	if m.autoSave || m.scanMode != "ALL" || m.regionMode != scanner.RegionModeCurrent || m.focusIdx != 0 {
		t.Fatal("typing changed configuration")
	}
	m, _ = updateModel(t, m, tea.KeyMsg{Type: tea.KeyCtrlR})
	m, _ = updateModel(t, m, tea.KeyMsg{Type: tea.KeyCtrlR})
	m, _ = updateModel(t, m, tea.KeyMsg{Type: tea.KeyTab})
	m, _ = updateModel(t, m, tea.KeyMsg{Type: tea.KeyTab})
	for _, r := range "eu-west-1,ap-south-1" {
		m, _ = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	if m.inputs[2].Value() != "eu-west-1,ap-south-1" || m.regionMode != scanner.RegionModeCustom {
		t.Fatalf("region input corrupted: %q", m.inputs[2].Value())
	}
}

func TestCustomScopeRequiresRegions(t *testing.T) {
	m := InitialModel()
	m.state, m.regionMode, m.focusIdx = StateConfig, scanner.RegionModeCustom, 2
	m, cmd := updateModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != StateConfig || cmd != nil || m.statusMsg == "" {
		t.Fatal("started a scan with an empty custom scope")
	}
}

func TestSearchUpdatesWhileTyping(t *testing.T) {
	m := InitialModel()
	m.state = StateDone
	m, _ = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	m, _ = updateModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("bucket")})
	if m.searchFilter != "bucket" {
		t.Fatalf("search filter = %q", m.searchFilter)
	}
}

func TestScanCommandKeepsWriterInLiveModelAndStreamsResults(t *testing.T) {
	t.Chdir(t.TempDir())
	m := InitialModel()
	m.state, m.focusIdx, m.autoSave = StateConfig, 1, true
	m.runScan = func(ctx context.Context, send func(tea.Msg), conf scanner.AuditConfig) {
		send(ghostAws.RegionsMsg{"eu-west-1"})
		send(ghostAws.FoundMsg{ID: "first-result", Service: "EC2"})
		send(ghostAws.ScanErrorMsg{Service: "S3", Error: "denied"})
		send(ghostAws.FinishedMsg{})
	}
	m, start := updateModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	defer func() { m.Close() }()
	if m.streamWriter == nil {
		t.Fatal("auto-save writer lost through a copied model")
	}
	filename := m.streamWriter.GetFilename()
	// Run the producer and consumer commands exactly as Bubble Tea's Batch does.
	batch := start().(tea.BatchMsg)
	done := make(chan struct{})
	go func() { batch[0](); close(done) }()
	cmd := batch[1]
	for m.state != StateDone {
		if cmd == nil {
			t.Fatal("event subscription stopped before scan completed")
		}
		m, cmd = updateModel(t, m, cmd())
	}
	<-done
	if len(m.resultList) != 1 || len(m.scanErrors) != 1 || m.streamWriter != nil {
		t.Fatalf("scan did not finish correctly: results=%v errors=%v", m.resultList, m.scanErrors)
	}
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"first-result", "SCAN ERROR", "eu-west-1", "denied"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("auto-save missing %q: %s", want, raw)
		}
	}
}

func TestEscapeCancelsScanAndStillCompletes(t *testing.T) {
	m := InitialModel()
	m.state, m.focusIdx = StateConfig, 1
	started := make(chan struct{})
	m.runScan = func(ctx context.Context, send func(tea.Msg), conf scanner.AuditConfig) {
		close(started)
		<-ctx.Done()
	}
	m, start := updateModel(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	defer func() { m.Close() }()
	batch := start().(tea.BatchMsg)
	done := make(chan struct{})
	go func() { batch[0](); close(done) }()
	<-started
	m, _ = updateModel(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("scan ignored escape")
	}
	m, _ = updateModel(t, m, batch[1]())
	if m.state != StateDone {
		t.Fatal("canceled scan stayed in scanning state")
	}
}
