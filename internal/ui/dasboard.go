package ui

import (
	"fmt"
	"strings"
	"time"

	ghostAws "github.com/K0NGR3SS/GhostState/internal/aws"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const logo = `
   ________               __  _____ __        __
  / ____/ /_  ____  _____/ /_/ ___// /_____ _/ /____
 / / __/ __ \/ __ \/ ___/ __/\__ \/ __/ __  / __/ _ \
/ /_/ / / / / /_/ (__  ) /_ ___/ / /_/ /_/ / /_/  __/
\____/_/ /_/\____/____/\__//____/\__/\__,_/\__/\___/ 
`
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
	colorOrange = lipgloss.Color("#FF9E64")
)

var (
	titleStyle     = lipgloss.NewStyle().Bold(true).Foreground(colorGold).MarginBottom(1)
	headerStyle    = lipgloss.NewStyle().Background(colorGold).Foreground(colorDark).Bold(true).Padding(0, 1).MarginTop(1).MarginBottom(1)
	sectionStyle   = lipgloss.NewStyle().Foreground(colorBlue).Bold(true).Underline(true).MarginTop(1)
	selectedStyle  = lipgloss.NewStyle().Foreground(colorWhite).Bold(true).PaddingLeft(1)
	
	inputStyle     = lipgloss.NewStyle().Foreground(colorGold)
	resultCatStyle = lipgloss.NewStyle().Foreground(colorBlue).Bold(true).MarginTop(1).PaddingLeft(1)

	styleCritical = lipgloss.NewStyle().Foreground(colorWhite).Background(colorRed).Bold(true).PaddingLeft(2)
	styleHigh     = lipgloss.NewStyle().Foreground(colorRed).Bold(true).PaddingLeft(2)
	styleMedium   = lipgloss.NewStyle().Foreground(colorOrange).PaddingLeft(2)
	styleLow      = lipgloss.NewStyle().Foreground(colorBlue).PaddingLeft(2)
	styleSafe     = lipgloss.NewStyle().Foreground(colorGreen).PaddingLeft(2)
)

type Model struct {
	state     int
	choices   []string
	selected  map[int]bool
	cursor    int
	inputs    []textinput.Model
	focusIdx  int
	results   map[string][]scanner.Resource
	spinner   spinner.Model
	startTime time.Time
	duration  time.Duration
	scanMode  string 
}

func InitialModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Meter
	s.Style = lipgloss.NewStyle().Foreground(colorGold)

	tKey := textinput.New()
	tKey.Placeholder = "Tag Key (e.g. CohortKey)"
	tKey.Focus()
	tKey.CharLimit = 30
	tKey.Width = 30
	tKey.PromptStyle = inputStyle
	tKey.TextStyle = inputStyle

	tVal := textinput.New()
	tVal.Placeholder = "Tag Value (e.g. Cohort)"
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
		"  EKS Clusters (K8s)",         
		"  ECR Repositories",           
		"DATA & STORAGE",               
		"  S3 Buckets",                 
		"  RDS Databases",              
		"  DynamoDB Tables",            
		"  ElastiCache Clusters",       
		"  EBS Volumes",                
		"NETWORKING",                   
		"  VPC Stack (VPC/Subnets)",    
		"  CloudFront Distributions",   
		"  Elastic IPs (EIP)",          
		"  Load Balancers (ELB)",       
		"SECURITY & IDENTITY",          
		"  Security Groups",            
		"  ACM Certificates",           
		"  IAM Users",                  
		"  Secrets Manager",            
		"  KMS Keys",                   
		"MONITORING",                   
		"  CloudWatch Alarms",          
	}

	sel := make(map[int]bool)
	for i := range choices {
		sel[i] = true
	}

	return Model{
		state:    StateMenu,
		choices:  choices,
		selected: sel,
		cursor:   0,
		inputs:   []textinput.Model{tKey, tVal},
		focusIdx: 0,
		results:  make(map[string][]scanner.Resource),
		spinner:  s,
		scanMode: "ALL",
	}
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

		if m.state == StateMenu {
			switch msg.String() {
			case "up", "k":
				if m.cursor > 0 { m.cursor-- }
			case "down", "j":
				if m.cursor < len(m.choices)-1 { m.cursor++ }
			case " ":
				m.handleSelection()
			case "enter":
				m.state = StateConfig
			}
		} else if m.state == StateConfig {
			switch msg.String() {
			case "m", "M":
				if m.scanMode == "ALL" { m.scanMode = "RISK" } else if m.scanMode == "RISK" { m.scanMode = "GHOST" } else { m.scanMode = "ALL" }
				return m, nil
			case "tab", "shift+tab", "enter":
				if m.focusIdx == len(m.inputs)-1 && msg.String() == "enter" {
					m.state = StateScan
					m.startTime = time.Now()
					return m, m.startScanCmd()
				}
				m.handleInputFocus(msg.String())
			}
		} else if m.state == StateDone {
			if msg.String() == "q" { return m, tea.Quit }
		}

	case ghostAws.FoundMsg:
		res := scanner.Resource(msg)
		cat := getCategory(res.Type)
		m.results[cat] = append(m.results[cat], res)
		return m, nil

	case ghostAws.FinishedMsg:
		m.duration = time.Since(m.startTime)
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
	case 0: // ALL
		for i := range m.choices { m.selected[i] = val }
	case 1: // COMPUTING
		for i := 2; i <= 6; i++ { m.selected[i] = val }
	case 7: // DATA
		for i := 8; i <= 12; i++ { m.selected[i] = val }
	case 13: // NETWORKING
		for i := 14; i <= 17; i++ { m.selected[i] = val }
	case 18: // SECURITY
		for i := 19; i <= 23; i++ { m.selected[i] = val }
	case 24: // MONITORING
		m.selected[25] = val
	}
}

func (m *Model) handleInputFocus(key string) {
	if key == "shift+tab" { m.focusIdx-- } else { m.focusIdx++ }
	if m.focusIdx >= len(m.inputs) { m.focusIdx = 0 }
	if m.focusIdx < 0 { m.focusIdx = len(m.inputs) - 1 }
	
	for i := range m.inputs {
		if i == m.focusIdx { m.inputs[i].Focus() } else { m.inputs[i].Blur() }
	}
}

func (m Model) startScanCmd() tea.Cmd {
	return func() tea.Msg {
		// [FIX] Trim whitespace so " Cohort " matches "Cohort"
		rawKeys := strings.TrimSpace(m.inputs[0].Value())
		rawVals := strings.TrimSpace(m.inputs[1].Value())
		
		conf := scanner.AuditConfig{
			ScanEC2: m.selected[2], ScanECS: m.selected[3], ScanLambda: m.selected[4],
			ScanEKS: m.selected[5], ScanECR: m.selected[6],
			ScanS3: m.selected[8], ScanRDS: m.selected[9], ScanDynamoDB: m.selected[10], 
			ScanElasti: m.selected[11], ScanEBS: m.selected[12],
			ScanVPC: m.selected[14], ScanCloudfront: m.selected[15], 
			ScanEIP: m.selected[16], ScanELB: m.selected[17],
			ScanSecGroups: m.selected[19], ScanACM: m.selected[20], 
			ScanIAM: m.selected[21], ScanSecrets: m.selected[22], ScanKMS: m.selected[23],
			ScanCloudWatch: m.selected[25],

			TargetRule: scanner.AuditRule{
				TargetKey: rawKeys,
				TargetVal: rawVals,
				ScanMode: m.scanMode,
			},
		}

		go ghostAws.ScanAll(Program, conf)
		return nil
	}
}

func (m *Model) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(m.inputs))
	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}
	return tea.Batch(cmds...)
}

func getCategory(resType string) string {
	resType = strings.ToLower(resType)
	isType := func(t string) bool { return strings.Contains(resType, strings.ToLower(t)) }

	if isType("vpc") || isType("subnet") || isType("gateway") || isType("cloudfront") || isType("eip") || isType("load balancer") { return "NETWORKING" }
	if isType("ec2") || isType("ecs") || isType("lambda") || isType("eks") || isType("ecr") { return "COMPUTING" }
	if isType("s3") || isType("rds") || isType("dynamodb") || isType("elasticache") || isType("ebs") { return "DATA & STORAGE" }
	if isType("security group") || isType("acm") || isType("iam") || isType("secret") || isType("kms") { return "SECURITY & IDENTITY" }
	if isType("cloudwatch") || isType("alarm") { return "MONITORING" }
	if isType("error") || isType("fatal") { return "ERRORS" }
	return "OTHER"
}

func cleanTypeString(t string) string {
	t = strings.ReplaceAll(t, "👻", "")
	t = strings.ReplaceAll(t, "🚨", "")
	t = strings.ReplaceAll(t, "🛡️", "")
	t = strings.ReplaceAll(t, "⚠️", "")
	t = strings.ReplaceAll(t, "💀", "")
	t = strings.ReplaceAll(t, "👤", "")
	t = strings.ReplaceAll(t, "[", "")
	t = strings.ReplaceAll(t, "]", "")
	return strings.TrimSpace(t)
}

func (m Model) renderResults() string {
	s := ""
	categories := []string{"COMPUTING", "DATA & STORAGE", "NETWORKING", "SECURITY & IDENTITY", "MONITORING", "ERRORS", "OTHER"}

	for _, cat := range categories {
		if items, ok := m.results[cat]; ok && len(items) > 0 {
			s += resultCatStyle.Render(cat) + "\n"
			for _, item := range items {
				cleanType := cleanTypeString(item.Type)
				line := fmt.Sprintf("[%s] %s", cleanType, item.ID)
				if item.Info != "" { line += fmt.Sprintf(" (%s)", item.Info) }
				
				switch item.Risk {
				case "CRITICAL": s += styleCritical.Render("💀 " + line) + "\n"
				case "HIGH":     s += styleHigh.Render("🚨 " + line) + "\n"
				case "MEDIUM":   s += styleMedium.Render("⚠️  " + line) + "\n"
				case "LOW":      s += styleLow.Render("👻 " + line) + "\n"
				case "SAFE":     s += styleSafe.Render("🛡️ " + line) + "\n"
				default:         s += styleLow.Render("👻 " + line) + "\n"
				}
			}
			s += "\n"
		}
	}
	return s
}

func (m Model) View() string {
	s := lipgloss.NewStyle().Foreground(colorGold).Render(logo) + "\n"
	s += titleStyle.Render("GHOSTSTATE v1.0") + "\n"

	switch m.state {
	case StateMenu:
		s += headerStyle.Render(" 1. SELECT TARGETS ") + "\n"
		for i, choice := range m.choices {
			cursor := " "
			if m.cursor == i { cursor = ">" }
			checked := "[ ]"
			if m.selected[i] { checked = "[x]" }
			line := fmt.Sprintf("%s %s %s", cursor, checked, choice)
			if i == 0 || i == 1 || i == 7 || i == 13 || i == 18 || i == 24 {
				s += sectionStyle.Render(line) + "\n"
			} else {
				s += selectedStyle.Render(line) + "\n"
			}
		}
	case StateConfig:
		s += headerStyle.Render(" 2. AUDIT RULE ") + "\n"
		s += fmt.Sprintf("SCAN MODE: %s (Press 'm' to toggle)\n\n", sectionStyle.Render(m.scanMode))
		for i := range m.inputs { s += m.inputs[i].View() + "\n" }
	case StateScan:
		s += headerStyle.Render(" 3. SCANNING... ") + "\n" + m.spinner.View() + "\n"
		s += m.renderResults()
	case StateDone:
		s += headerStyle.Render(" 4. REPORT ") + "\n"
		s += m.renderResults()
		total := 0
		for _, v := range m.results { total += len(v) }
		s += fmt.Sprintf("Found %d resources in %s. [Q] Quit", total, m.duration.Round(time.Millisecond))
	}
	return s
}