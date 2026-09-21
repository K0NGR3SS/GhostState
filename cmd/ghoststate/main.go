package main

import (
	"fmt"
	"os"

	"github.com/K0NGR3SS/GhostState/internal/ui"
	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	m := ui.InitialModel()

	p := tea.NewProgram(m)

	finalModel, err := p.Run()
	if model, ok := finalModel.(ui.Model); ok {
		model.Close()
	}
	if err != nil {
		fmt.Printf("Error running GhostState: %v\n", err)
		os.Exit(1)
	}
}
