package ui

import (
	"fmt"

	"github.com/K0NGR3SS/GhostState/internal/aws"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// --- STYLES ---
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Background(lipgloss.Color("#7D56F4")).
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1).
			MarginBottom(1)

	ghostStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5F87")).
			PaddingLeft(2).
			SetString("👻 ")

	statusStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262")).
			PaddingTop(1)
)

type Model struct {
	results  []string
	scanning bool
	spinner  spinner.Model
}

func InitialModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return Model{
		results:  []string{},
		scanning: true,
		spinner:  s,
	}
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

type startScanMsg struct{}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case startScanMsg:
		return m, nil

	case aws.FoundMsg:
		m.results = append(m.results, string(msg))
		return m, nil

	case aws.FinishedMsg:
		m.scanning = false
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) View() string {
	s := "\n" + titleStyle.Render(" GHOST STATE ") + "\n"

	// SECTION 1: The List of Ghosts
	if len(m.results) > 0 {
		for _, res := range m.results {
			s += ghostStyle.Render(res) + "\n"
		}
	} else if !m.scanning {
		s += "  🌿 System Clean. No drift detected.\n"
	}

	// SECTION 2: Footer / Status
	s += "\n"
	if m.scanning {
		// Show Spinner + Text
		s += fmt.Sprintf(" %s Scanning AWS Resources...", m.spinner.View())
	} else {
		// Show Summary
		count := len(m.results)
		s += statusStyle.Render(fmt.Sprintf("Scan Complete. Found %d ghosts.", count))
		s += "\n Press 'q' to quit."
	}

	return s + "\n"
}
