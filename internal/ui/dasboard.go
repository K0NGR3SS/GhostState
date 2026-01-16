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
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorGold).
			MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
			Foreground(colorWhite).
			Bold(true).
			Underline(true).
			MarginBottom(1)

	checkboxStyle = lipgloss.NewStyle().Foreground(colorGray).PaddingLeft(1)
	selectedStyle = lipgloss.NewStyle().Foreground(colorGold).Bold(true).PaddingLeft(1)

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

	return Model{
		state:    StateMenu,
		choices:  []string{"Scan EC2 Instances", "Scan S3 Buckets"},
		selected: map[int]bool{0: true, 1: true},
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
	ScanEC2   bool
	ScanS3    bool
	TargetKey string
	TargetVal string
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		if m.state == StateMenu {
			switch msg.String() {
			case "q":
				return m, tea.Quit
			case "up", "k":
				if m.cursor > 0 { m.cursor-- }
			case "down", "j":
				if m.cursor < len(m.choices)-1 { m.cursor++ }
			case " ":
				m.selected[m.cursor] = !m.selected[m.cursor]
			case "enter":
				m.state = StateConfig
				return m, nil
			}
		}

		if m.state == StateConfig {
			switch msg.String() {
			case "tab", "shift+tab", "enter":
				if m.focusIdx == len(m.inputs)-1 {
					if msg.String() == "enter" {
						m.state = StateScan
						
						key := m.inputs[0].Value()
						val := m.inputs[1].Value()

						if key == "" { key = "ManagedBy" }
						if val == "" { val = "Terraform" }

						return m, func() tea.Msg {
							return StartScanMsg{
								ScanEC2:   m.selected[0],
								ScanS3:    m.selected[1],
								TargetKey: key,
								TargetVal: val,
							}
						}
					}
				}
				if msg.String() == "enter" || msg.String() == "tab" {
					m.focusIdx++
					if m.focusIdx >= len(m.inputs) { m.focusIdx = 0 }
				} else if msg.String() == "shift+tab" {
					m.focusIdx--
					if m.focusIdx < 0 { m.focusIdx = len(m.inputs) - 1 }
				}

				cmds := make([]tea.Cmd, len(m.inputs))
				for i := 0; i < len(m.inputs); i++ {
					if i == m.focusIdx {
						cmds[i] = m.inputs[i].Focus()
						m.inputs[i].PromptStyle = inputStyle
						m.inputs[i].TextStyle = inputStyle
					} else {
						m.inputs[i].Blur()
						m.inputs[i].PromptStyle = lipgloss.NewStyle().Foreground(colorGray)
						m.inputs[i].TextStyle = lipgloss.NewStyle().Foreground(colorGray)
					}
				}
				return m, tea.Batch(cmds...)
			}
		}

		if m.state == StateDone {
			if msg.String() == "q" {
				return m, tea.Quit
			}
		}

	case StartScanMsg:
		if Program != nil {
			cfg := aws.AuditConfig{
				ScanEC2:   msg.ScanEC2,
				ScanS3:    msg.ScanS3,
				Mode:      "MISSING_SPECIFIC_TAG",
				TargetKey: msg.TargetKey,
				TargetVal: msg.TargetVal,
			}
			go aws.ScanAll(Program, cfg)
		}
		return m, nil

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
		cmd := m.updateInputs(msg)
		return m, cmd
	}

	return m, nil
}

func (m *Model) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))
	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}
	return tea.Batch(cmds...)
}


func (m Model) View() string {
		title := `
	  ________.__                    __   _________ __          __          
	 /  _____/|  |__   ____  _______/  |_/   _____//  |______ _/  |_  ____  
	/   \  ___|  |  \ /  _ \/  ___/\   __\_____  \\   __\__  \\   __\/ __ \ 
	\    \_\  \   Y  (  <_> )___ \  |  | /        \|  |  / __ \|  | \  ___/ 
	 \______  /___|  /\____/____  > |__|/_______  /|__| (____  /__|  \___  >
			\/     \/           \/              \/           \/          \/ 
	`
		s := titleStyle.Render(title) + "\n\n"

	if m.state == StateMenu {
		s += headerStyle.Render("1. SELECT TARGETS") + "\n\n"
		for i, choice := range m.choices {
			cursor := " "
			if m.cursor == i { cursor = ">" }
			checked := "[ ]"
			if m.selected[i] { checked = "[x]" }
			
			line := fmt.Sprintf("%s %s %s", cursor, checked, choice)
			if m.cursor == i {
				s += selectedStyle.Render(line) + "\n"
			} else {
				s += checkboxStyle.Render(line) + "\n"
			}
		}
		s += "\n[Space] Toggle  [Enter] Next  [Q] Quit\n"
	}

	if m.state == StateConfig {
		s += headerStyle.Render("2. CONFIGURE AUDIT RULE") + "\n\n"
		s += "Define the 'Safe Tag' that resources MUST have.\n"
		s += "Resources missing this tag will be flagged.\n\n"
		
		for i := range m.inputs {
			s += m.inputs[i].View() + "\n\n"
		}
		
		s += "[Tab] Next Field  [Enter] START SCAN\n"
	}

	if m.state == StateScan {
		s += headerStyle.Render("3. SCANNING CLOUD") + "\n\n"
		s += fmt.Sprintf(" %s Searching for ghosts...", m.spinner.View()) + "\n\n"

		for _, res := range m.results {
			s += ghostStyle.Render(res) + "\n"
		}
	}

	if m.state == StateDone {
		s += headerStyle.Render("4. AUDIT REPORT") + "\n\n"
		if len(m.results) == 0 {
			s += cleanStyle.Render("All systems clean. No drift detected.") + "\n"
		} else {
			for _, res := range m.results {
				s += ghostStyle.Render(res) + "\n"
			}
			s += fmt.Sprintf("\nFound %d unmanaged resources.", len(m.results))
		}
		s += "\n\n[Q] Quit\n"
	}

	return s
}
