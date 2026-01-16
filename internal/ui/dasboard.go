package ui

import (
	"github.com/K0NGR3SS/GhostState/internal/aws"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#7D56F4")).Foreground(lipgloss.Color("#FFF")).Padding(0, 1)
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F87"))
)

type Model struct {
	results  []string
	scanning bool
}

func InitialModel() Model {
	return Model{
		results:  []string{},
		scanning: true,
	}
}

func (m Model) Init() tea.Cmd {
	return func() tea.Msg {
		return startScanMsg{}
	}
}

type startScanMsg struct{}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	// The start message triggers the actual Go routine
	case startScanMsg:
		return m, func() tea.Msg {
			// BAsic for now
		}

	case aws.FoundMsg:
		m.results = append(m.results, string(msg))
		return m, nil

	case aws.FinishedMsg:
		m.scanning = false
		return m, nil
	}

	return m, nil
}

func (m Model) View() string {
	s := "\n" + titleStyle.Render(" GHOST STATE ") + "\n\n"

	if m.scanning {
		s += "Scanning AWS (EC2 + S3)...\n\n"
	} else {
		s += " Scan Complete.\n\n"
	}

	for _, res := range m.results {
		s += warnStyle.Render(res) + "\n"
	}

	if !m.scanning {
		s += "\nPress 'q' to quit.\n"
	}
	return s
}
