package ui

import (
	"fmt"

	"github.com/K0NGR3SS/GhostState/internal/aws"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	StateMenu     = 0
	StateScanning = 1
	StateDone     = 2
)

var Program *tea.Program

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#7D56F4")).Foreground(lipgloss.Color("#FFF")).Padding(0, 1)
	ghostStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F87")).PaddingLeft(2).SetString("👻 ")
	
	checkboxStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("212")).PaddingLeft(1)
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true).PaddingLeft(1)
)

type Model struct {
	state    int
	choices  []string
	selected map[int]bool
	cursor   int

	results  []string
	spinner  spinner.Model
}

func InitialModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return Model{
		state:    StateMenu,
		choices:  []string{"Scan EC2 Instances", "Scan S3 Buckets"},
		selected: map[int]bool{0: true, 1: true},
		cursor:   0,
		results:  []string{},
		spinner:  s,
	}
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

type StartScanMsg struct {
	ScanEC2 bool
	ScanS3  bool
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		if m.state == StateMenu {
			switch msg.String() {
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.choices)-1 {
					m.cursor++
				}
			case " ":
				m.selected[m.cursor] = !m.selected[m.cursor]
			case "enter":
				m.state = StateScanning
				return m, func() tea.Msg {
					return StartScanMsg{
						ScanEC2: m.selected[0],
						ScanS3:  m.selected[1],
					}
				}
			}
		}

	case StartScanMsg:
		if Program != nil {
			go aws.ScanAll(Program, msg.ScanEC2, msg.ScanS3)
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

	return m, nil
}

func (m Model) View() string {
	s := "\n" + titleStyle.Render(" GHOST STATE ") + "\n\n"

	if m.state == StateMenu {
		s += "Select resources to scan (Space to toggle, Enter to start):\n\n"
		
		for i, choice := range m.choices {
			cursor := " "
			if m.cursor == i {
				cursor = ">"
			}

			checked := "[ ]"
			if m.selected[i] {
				checked = "[x]"
			}

			line := fmt.Sprintf("%s %s %s", cursor, checked, choice)
			
			if m.cursor == i {
				s += selectedStyle.Render(line) + "\n"
			} else {
				s += checkboxStyle.Render(line) + "\n"
			}
		}
		s += "\nPress 'q' to quit.\n"
		return s
	}

	if len(m.results) > 0 {
		for _, res := range m.results {
			s += ghostStyle.Render(res) + "\n"
		}
	} else if m.state == StateDone {
		s += "  🌿 System Clean. No drift detected.\n"
	}

	s += "\n"
	if m.state == StateScanning {
		s += fmt.Sprintf(" %s Scanning Selected Resources...", m.spinner.View())
	} else {
		s += fmt.Sprintf("Scan Complete. Found %d items.\n Press 'q' to quit.", len(m.results))
	}

	return s + "\n"
}