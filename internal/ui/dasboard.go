package ui

import (
	"fmt"
	"github.com/K0NGR3SS/GhostState/internal/aws"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	StateMenu   = 0
	StateConfig = 1
	StateScan   = 2
	StateDone   = 3
)

var Program *tea.Program

var (
	colorGold   = lipgloss.Color("#F2C85B")
	colorDark   = lipgloss.Color("#1A1B26")
	colorGray   = lipgloss.Color("#565F89")
	colorWhite  = lipgloss.Color("#C0CAF5")
	colorRed    = lipgloss.Color("#F7768E")
	colorGreen  = lipgloss.Color("#9ECE6A")
	colorBlue   = lipgloss.Color("#7AA2F7")
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(colorGold).MarginBottom(1)
	headerStyle = lipgloss.NewStyle().Background(colorGold).Foreground(colorDark).Bold(true).Padding(0, 1).MarginTop(1).MarginBottom(1)
	sectionStyle = lipgloss.NewStyle().Foreground(colorBlue).Bold(true).Underline(true).MarginTop(1)
	
	checkboxStyle = lipgloss.NewStyle().Foreground(colorGray).PaddingLeft(1)
	selectedStyle = lipgloss.NewStyle().Foreground(colorWhite).Bold(true).PaddingLeft(1)

	ghostStyle = lipgloss.NewStyle().Foreground(colorRed).PaddingLeft(2).SetString("👻 ")
	cleanStyle = lipgloss.NewStyle().Foreground(colorGreen).PaddingLeft(2).SetString("🛡️ ")
	inputStyle = lipgloss.NewStyle().Foreground(colorGold)
)

type Model struct {
	state    int
	choices  []string
	selected map[int]bool
	cursor   int
	inputs   []textinput.Model
	focusIdx int
	results  []string
	spinner  spinner.Model
}

func InitialModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Meter
	s.Style = lipgloss.NewStyle().Foreground(colorGold)

	tKey := textinput.New()
	tKey.Placeholder = "Key (e.g. ManagedBy)"
	tKey.Focus()
	tKey.CharLimit = 30
	tKey.Width = 30
	tKey.PromptStyle = inputStyle
	tKey.TextStyle = inputStyle

	tVal := textinput.New()
	tVal.Placeholder = "Value (e.g. Terraform)"
	tVal.CharLimit = 30
	tVal.Width = 30
	tVal.PromptStyle = inputStyle
	tVal.TextStyle = inputStyle

	choices := []string{
		"ALL SERVICES",
		"COMPUTING",
		"  EC2 Instances",
		"  ECS Clusters",
		"  Lambda Functions",
		"DATA & STORAGE",
		"  S3 Buckets",
		"  RDS Databases",
		"  DynamoDB Tables",
		"  ElastiCache Clusters",
		"NETWORKING & SECURITY",
		"  VPC Stack (VPC, Subnets, IGW)",
		"  CloudFront Distributions",
		"  ACM Certificates",
		"  Security Groups",
	}

	sel := make(map[int]bool)
	for i := range choices { sel[i] = true }

	return Model{
		state:    StateMenu,
		choices:  choices,
		selected: sel,
		cursor:   0,
		inputs:   []textinput.Model{tKey, tVal},
		focusIdx: 0,
		results:  []string{},
		spinner:  s,
	}
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

type StartScanMsg struct {
	ScanEC2, ScanS3, ScanRDS, ScanElasti, ScanACM, ScanSecGroups, ScanECS, ScanCloudfront, ScanLambda, ScanDynamoDB, ScanVPC bool
	TargetKey string
	TargetVal string
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" { return m, tea.Quit }

		if m.state == StateMenu {
			switch msg.String() {
			case "up", "k": if m.cursor > 0 { m.cursor-- }
			case "down", "j": if m.cursor < len(m.choices)-1 { m.cursor++ }
			case " ": m.handleSelection()
			case "enter": m.state = StateConfig
			}
		} else if m.state == StateConfig {
			switch msg.String() {
			case "tab", "shift+tab", "enter":
				if m.focusIdx == len(m.inputs)-1 && msg.String() == "enter" {
					m.state = StateScan
					return m, m.startScanCmd()
				}
				m.handleInputFocus(msg.String())
			}
		} else if m.state == StateDone {
			if msg.String() == "q" { return m, tea.Quit }
		}

	case aws.FoundMsg:
		m.results = append(m.results, string(msg))
		return m, nil

	case aws.FinishedMsg:
		m.state = StateDone
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	if m.state == StateConfig {
		return m, m.updateInputs(msg)
	}
	return m, nil
}

func (m *Model) handleSelection() {
	m.selected[m.cursor] = !m.selected[m.cursor]
	val := m.selected[m.cursor]
	switch m.cursor {
	case 0: for i := range m.choices { m.selected[i] = val }
	case 1: for i := 2; i <= 4; i++ { m.selected[i] = val }
	case 5: for i := 6; i <= 9; i++ { m.selected[i] = val }
	case 10: for i := 11; i <= 14; i++ { m.selected[i] = val }
	}
}

func (m *Model) handleInputFocus(key string) {
	if key == "shift+tab" {
		m.focusIdx--
	} else {
		m.focusIdx++
	}
	if m.focusIdx >= len(m.inputs) { m.focusIdx = 0 }
	if m.focusIdx < 0 { m.focusIdx = len(m.inputs) - 1 }
	for i := range m.inputs {
		if i == m.focusIdx { m.inputs[i].Focus() } else { m.inputs[i].Blur() }
	}
}

func (m Model) startScanCmd() tea.Cmd {
	return func() tea.Msg {
		key, val := m.inputs[0].Value(), m.inputs[1].Value()
		if key == "" { key = "ManagedBy" }
		if val == "" { val = "Terraform" }
		go aws.ScanAll(Program, aws.AuditConfig{
			ScanEC2: m.selected[2], ScanECS: m.selected[3], ScanLambda: m.selected[4],
			ScanS3: m.selected[6], ScanRDS: m.selected[7], ScanDynamoDB: m.selected[8], ScanElasti: m.selected[9],
			ScanVPC: m.selected[11], ScanCloudfront: m.selected[12], ScanACM: m.selected[13], ScanSecGroups: m.selected[14],
			TargetKey: key, TargetVal: val,
		})
		return nil
	}
}

func (m *Model) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))
	for i := range m.inputs { m.inputs[i], cmds[i] = m.inputs[i].Update(msg) }
	return tea.Batch(cmds...)
}

func (m Model) View() string {
	s := titleStyle.Render("GHOSTSTATE v1.0") + "\n"
	switch m.state {
	case StateMenu:
		s += headerStyle.Render(" 1. SELECT TARGETS ") + "\n"
		for i, choice := range m.choices {
			cursor := " "; if m.cursor == i { cursor = ">" }
			checked := "[ ]"; if m.selected[i] { checked = "[x]" }
			line := fmt.Sprintf("%s %s %s", cursor, checked, choice)
			if i == 0 || i == 1 || i == 5 || i == 10 { s += sectionStyle.Render(line) + "\n" } else { s += selectedStyle.Render(line) + "\n" }
		}
	case StateConfig:
		s += headerStyle.Render(" 2. AUDIT RULE ") + "\n"
		for i := range m.inputs { s += m.inputs[i].View() + "\n" }
	case StateScan:
		s += headerStyle.Render(" 3. SCANNING... ") + "\n" + m.spinner.View() + "\n"
		for _, res := range m.results { s += ghostStyle.Render(res) + "\n" }
	case StateDone:
		s += headerStyle.Render(" 4. REPORT ") + "\n"
		for _, res := range m.results { s += ghostStyle.Render(res) + "\n" }
		s += fmt.Sprintf("\nFound %d ghosts. [Q] Quit", len(m.results))
	}
	return s
}
