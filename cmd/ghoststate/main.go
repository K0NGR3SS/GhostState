package main

import (
	"fmt"
	"os"

	_ "github.com/K0NGR3SS/GhostState/internal/aws" 
	"github.com/K0NGR3SS/GhostState/internal/ui"
	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	m := ui.InitialModel()

	p := tea.NewProgram(m)

	ui.Program = p

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running GhostState: %v\n", err)
		os.Exit(1)
	}
}
