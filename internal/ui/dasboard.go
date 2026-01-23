package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	ghostAws "github.com/K0NGR3SS/GhostState/internal/aws"
	"github.com/K0NGR3SS/GhostState/internal/report"
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

const (
	ViewReport = 0
	ViewStats  = 1
	ViewCost   = 2
)

var Program *tea.Program

var (
	colorGold   = lipgloss.Color("#F2C85B")
	colorDark   = lipgloss.Color("#1A1B26")
	colorGray   = lipgloss.Color("#565F89")
	colorWhite  = lipgloss.Color("#C0CAF5")
	colorRed    = lipgloss.Color("#F7768E")
	colorRedDim = lipgloss.Color("#A54242")
	colorGreen  = lipgloss.Color("#9ECE6A")
	colorBlue   = lipgloss.Color("#7AA2F7")
	colorOrange = lipgloss.Color("#FF9E64")
	colorBlack  = lipgloss.Color("#000000")
)

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(colorGold).MarginBottom(1)
	headerStyle  = lipgloss.NewStyle().Background(colorGold).Foreground(colorDark).Bold(true).Padding(0, 1).MarginTop(1).MarginBottom(1)
	sectionStyle = lipgloss.NewStyle().Foreground(colorBlue).Bold(true).Underline(true).MarginTop(1)
	selectedStyle = lipgloss.NewStyle().Foreground(colorWhite).Bold(true).PaddingLeft(1)

	inputStyle     = lipgloss.NewStyle().Foreground(colorGold)
	resultCatStyle = lipgloss.NewStyle().Foreground(colorBlue).Bold(true).MarginTop(1).PaddingLeft(1)

	styleCritical = lipgloss.NewStyle().Foreground(colorWhite).Background(colorRedDim).Bold(true).PaddingLeft(2)
	styleHigh     = lipgloss.NewStyle().Foreground(colorRed).Bold(true).PaddingLeft(2)
	styleMedium   = lipgloss.NewStyle().Foreground(colorOrange).PaddingLeft(2)
	styleLow      = lipgloss.NewStyle().Foreground(colorBlue).PaddingLeft(2)
	styleSafe     = lipgloss.NewStyle().Foreground(colorGreen).PaddingLeft(2)

	styleTime  = lipgloss.NewStyle().Foreground(colorGray).Bold(true)
	styleMoney = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)

	modalStyle = lipgloss.NewStyle().
			Width(80).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorGold).
			Padding(1, 2).
			Background(colorDark)

	modalTitleStyle = lipgloss.NewStyle().
			Foreground(colorGold).
			Bold(true).
			Underline(true).
			MarginBottom(1)
)

type Model struct {
	state    int
	choices  []string
	selected map[int]bool
	cursor   int

	inputs   []textinput.Model
	focusIdx int

	results map[string][]scanner.Resource

	spinner   spinner.Model
	startTime time.Time
	duration  time.Duration
	scanMode  string
	statusMsg string

	resultList     []scanner.Resource
	resultCursor   int
	resultViewMode int

	showModal bool
	modalItem scanner.Resource

	totalCost float64

	width        int
	height       int
	scrollOffset int
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
		"  Route53 Hosted Zones",
		"SECURITY & IDENTITY",
		"  Security Groups",
		"  ACM Certificates",
		"  IAM Users",
		"  Secrets Manager",
		"  KMS Keys",
		"  CloudTrail Trails",
		"MONITORING",
		"  CloudWatch Alarms",
	}

	sel := make(map[int]bool)
	for i := range choices {
		sel[i] = true
	}

	return Model{
		state:          StateMenu,
		choices:        choices,
		selected:       sel,
		cursor:         0,
		inputs:         []textinput.Model{tKey, tVal},
		focusIdx:       0,
		results:        make(map[string][]scanner.Resource),
		spinner:        s,
		scanMode:       "ALL",
		statusMsg:      "",
		resultCursor:   0,
		resultViewMode: ViewReport,
		scrollOffset:   0,
	}
}

func (m Model) Init() tea.Cmd {
	return m.spinner.Tick
}

func isRiskFinding(r scanner.Resource) bool { return r.Risk == "CRITICAL" || r.Risk == "HIGH" || r.Risk == "MEDIUM" }
func includeByMode(mode string, r scanner.Resource) bool {
	switch mode {
	case "RISK":
		return isRiskFinding(r)
	case "GHOST":
		return r.IsGhost
	default:
		return true
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if msg.String() == "esc" {
			if m.showModal {
				m.showModal = false
				return m, nil
			}
			switch m.state {
			case StateConfig:
				m.state = StateMenu
				return m, nil
			case StateDone:
				m.results = make(map[string][]scanner.Resource)
				m.resultList = []scanner.Resource{}
				m.totalCost = 0
				m.state = StateMenu
				return m, nil
			}
		}
		if m.showModal {
			if msg.String() == "esc" || msg.String() == "enter" {
				m.showModal = false
			}
			return m, nil
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
				m.handleSelection()
			case "enter":
				m.state = StateConfig
			}
		} else if m.state == StateConfig {
			switch msg.String() {
			case "m", "M":
				if m.scanMode == "ALL" {
					m.scanMode = "RISK"
				} else if m.scanMode == "RISK" {
					m.scanMode = "GHOST"
				} else {
					m.scanMode = "ALL"
				}
			case "up", "k", "shift+tab":
				m.handleInputFocus("prev")
			case "down", "j", "tab":
				m.handleInputFocus("next")
			case "enter":
				if m.focusIdx == len(m.inputs)-1 {
					m.results = make(map[string][]scanner.Resource)
					m.resultList = []scanner.Resource{}
					m.totalCost = 0
					m.statusMsg = ""
					m.resultCursor = 0
					m.resultViewMode = ViewReport
					m.scrollOffset = 0
					m.state = StateScan
					m.startTime = time.Now()
					return m, m.startScanCmd()
				} else {
					m.handleInputFocus("next")
				}
			}
		} else if m.state == StateDone {
			switch msg.String() {
			case "q":
				return m, tea.Quit
			case "s", "S":
				filename, err := report.GenerateCSV(m.results)
				if err != nil {
					m.statusMsg = fmt.Sprintf("Error saving report: %v", err)
				} else {
					m.statusMsg = fmt.Sprintf("Report saved to %s", filename)
				}
				return m, nil

			case "tab":
				m.resultViewMode++
				if m.resultViewMode > ViewCost {
					m.resultViewMode = ViewReport
				}
				m.resultCursor = 0
				m.scrollOffset = 0

			case "up", "k":
				if m.resultCursor > 0 {
					m.resultCursor--
				}
			case "down", "j":
				listLen := len(m.resultList)
				if m.resultViewMode == ViewCost {
					listLen = len(m.getCostItems())
				}
				if m.resultCursor < listLen-1 {
					m.resultCursor++
				}
			case "enter":
				var sorted []scanner.Resource
				if m.resultViewMode == ViewCost {
					sorted = m.getCostItems()
				} else {
					sorted = m.getSortedItems()
				}
				if len(sorted) > 0 && m.resultCursor < len(sorted) {
					m.modalItem = sorted[m.resultCursor]
					m.showModal = true
				}
			}
		}

	case ghostAws.FoundMsg:
		res := scanner.Resource(msg)
		if !includeByMode(m.scanMode, res) {
			return m, nil
		}
		catKey := res.Service
		if catKey == "" {
			catKey = res.Type
		}
		cat := getCategory(catKey)
		m.results[cat] = append(m.results[cat], res)
		m.resultList = append(m.resultList, res)
		m.totalCost += res.MonthlyCost
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

func scoreRisk(risk string) int {
	switch risk {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func riskEmoji(r scanner.Resource) string {
	switch r.Risk {
	case "CRITICAL":
		return "💀"
	case "HIGH":
		return "🚨"
	case "MEDIUM":
		return "⚠️"
	case "LOW":
		return "🔹"
	case "SAFE":
		if r.IsGhost {
			return "👻"
		}
		return "🛡️"
	default:
		if r.IsGhost {
			return "👻"
		}
		return "•"
	}
}

func styleFor(r scanner.Resource) lipgloss.Style {
	switch r.Risk {
	case "CRITICAL":
		return styleCritical
	case "HIGH":
		return styleHigh
	case "MEDIUM":
		return styleMedium
	case "SAFE":
		if r.IsGhost {
			return styleLow
		}
		return styleSafe
	default:
		if r.IsGhost {
			return styleLow
		}
		return styleLow
	}
}

func categoryOrder() []string {
	return []string{"COMPUTING", "DATA & STORAGE", "NETWORKING", "SECURITY & IDENTITY", "MONITORING", "ERRORS", "OTHER"}
}

func renderLegend() string {
	parts := []string{
		styleCritical.Render("💀 CRITICAL"), styleHigh.Render("🚨 HIGH"),
		styleMedium.Render("⚠️  MEDIUM"), styleLow.Render("👻 GHOST/LOW"),
		styleSafe.Render("🛡️ SAFE"),
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...) + "\n\n"
}

func (m Model) getCostItems() []scanner.Resource {
	var costItems []scanner.Resource
	for _, r := range m.resultList {
		if r.MonthlyCost > 0 {
			costItems = append(costItems, r)
		}
	}
	sort.SliceStable(costItems, func(i, j int) bool { return costItems[i].MonthlyCost > costItems[j].MonthlyCost })
	return costItems
}

func (m Model) getSortedItems() []scanner.Resource {
	grouped := make(map[string][]scanner.Resource)
	for _, r := range m.resultList {
		catKey := r.Service
		if catKey == "" {
			catKey = r.Type
		}
		cat := getCategory(catKey)
		grouped[cat] = append(grouped[cat], r)
	}
	var sorted []scanner.Resource
	for _, cat := range categoryOrder() {
		items := grouped[cat]
		sort.SliceStable(items, func(i, j int) bool {
			ri := scoreRisk(items[i].Risk)
			rj := scoreRisk(items[j].Risk)
			if ri != rj {
				return ri > rj
			}
			if items[i].IsGhost != items[j].IsGhost {
				return items[i].IsGhost
			}
			return items[i].ID < items[j].ID
		})
		sorted = append(sorted, items...)
	}
	return sorted
}

func (m *Model) handleSelection() {
	m.selected[m.cursor] = !m.selected[m.cursor]
	val := m.selected[m.cursor]
	switch m.cursor {
	case 0:
		for i := range m.choices {
			m.selected[i] = val
		}
	case 1:
		for i := 2; i <= 6; i++ {
			m.selected[i] = val
		}
	case 7:
		for i := 8; i <= 12; i++ {
			m.selected[i] = val
		}
	case 13:
		for i := 14; i <= 18; i++ {
			m.selected[i] = val
		}
	case 19:
		for i := 20; i <= 25; i++ {
			m.selected[i] = val
		}
	case 26:
		m.selected[27] = val
	}
}

func (m *Model) handleInputFocus(direction string) {
	if direction == "prev" {
		m.focusIdx--
	} else {
		m.focusIdx++
	}
	if m.focusIdx >= len(m.inputs) {
		m.focusIdx = 0
	}
	if m.focusIdx < 0 {
		m.focusIdx = len(m.inputs) - 1
	}
	for i := range m.inputs {
		if i == m.focusIdx {
			m.inputs[i].Focus()
		} else {
			m.inputs[i].Blur()
		}
	}
}

func (m Model) startScanCmd() tea.Cmd {
	return func() tea.Msg {
		rawKeys := strings.TrimSpace(m.inputs[0].Value())
		rawVals := strings.TrimSpace(m.inputs[1].Value())
		conf := scanner.AuditConfig{
			ScanEC2: m.selected[2], ScanECS: m.selected[3], ScanLambda: m.selected[4], ScanEKS: m.selected[5], ScanECR: m.selected[6],
			ScanS3: m.selected[8], ScanRDS: m.selected[9], ScanDynamoDB: m.selected[10], ScanElasti: m.selected[11], ScanEBS: m.selected[12],
			ScanVPC: m.selected[14], ScanCloudfront: m.selected[15], ScanEIP: m.selected[16], ScanELB: m.selected[17], ScanRoute53: m.selected[18],
			ScanSecGroups: m.selected[20], ScanACM: m.selected[21], ScanIAM: m.selected[22], ScanSecrets: m.selected[23], ScanKMS: m.selected[24], ScanCloudTrail: m.selected[25],
			ScanCloudWatch: m.selected[27],
			TargetRule: scanner.AuditRule{TargetKey: rawKeys, TargetVal: rawVals, ScanMode: m.scanMode},
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
	if isType("vpc") || isType("subnet") || isType("gateway") || isType("cloudfront") || isType("eip") || isType("elastic ip") || isType("load balancer") || isType("route53") || isType("hosted zone") {
		return "NETWORKING"
	}
	if isType("ec2") || isType("ecs") || isType("lambda") || isType("eks") || isType("ecr") {
		return "COMPUTING"
	}
	if isType("s3") || isType("rds") || isType("dynamodb") || isType("elasticache") || isType("ebs") {
		return "DATA & STORAGE"
	}
	if isType("security group") || isType("acm") || isType("iam") || isType("secret") || isType("kms") || isType("cloudtrail") {
		return "SECURITY & IDENTITY"
	}
	if isType("cloudwatch") || isType("alarm") {
		return "MONITORING"
	}
	if isType("error") || isType("fatal") {
		return "ERRORS"
	}
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

func (m Model) renderHeaderContent() string {
	tab1 := " REPORT "
	tab2 := " STATS "
	tab3 := " COST "
	if m.resultViewMode == ViewReport {
		tab1 = lipgloss.NewStyle().Background(colorBlue).Foreground(colorBlack).Bold(true).Render(tab1)
	} else if m.resultViewMode == ViewStats {
		tab2 = lipgloss.NewStyle().Background(colorBlue).Foreground(colorBlack).Bold(true).Render(tab2)
	} else {
		tab3 = lipgloss.NewStyle().Background(colorGreen).Foreground(colorBlack).Bold(true).Render(tab3)
	}

	header := tab1 + "  " + tab2 + "  " + tab3 + "\n\n"
	if m.resultViewMode == ViewReport {
		header += renderLegend()
	}
	return header
}

func (m Model) renderListContent() string {
	var sb strings.Builder

	if m.resultViewMode == ViewStats {
		sb.WriteString(fmt.Sprintf("Total Resources: %d\n", len(m.resultList)))
		sb.WriteString(fmt.Sprintf("Total Estimated Spend: $%.2f/mo\n", m.totalCost))
		return sb.String()
	}

	if m.resultViewMode == ViewCost {
		items := m.getCostItems()
		sb.WriteString(styleMoney.Render("TOP SPENDERS (Highest Cost First)") + "\n\n")
		for i, item := range items {
			cursor := " "
			if i == m.resultCursor {
				cursor = ">"
			}
			line := fmt.Sprintf("%s 💰 $%-8.2f %s (%s)", cursor, item.MonthlyCost, item.ID, item.Type)
			sb.WriteString(lipgloss.NewStyle().Foreground(colorGreen).Render(line) + "\n")
		}
		if len(items) == 0 {
			sb.WriteString("No costs detected ($0.00).\n")
		}
		return sb.String()
	}

	sortedItems := m.getSortedItems()
	currentCat := ""
	for i, item := range sortedItems {
		catKey := item.Service
		if catKey == "" {
			catKey = item.Type
		}
		cat := getCategory(catKey)

		if cat != currentCat {
			sb.WriteString(resultCatStyle.Render(cat) + "\n")
			currentCat = cat
		}
		cursor := " "
		if i == m.resultCursor {
			cursor = ">"
		}
		emoji := riskEmoji(item)
		cleanType := cleanTypeString(item.Type)
		extra := ""
		if m.scanMode == "ALL" {
			if item.Risk != "" && item.Risk != "SAFE" {
				if item.RiskInfo != "" {
					extra = fmt.Sprintf(" (%s: %s)", item.Risk, item.RiskInfo)
				} else {
					extra = fmt.Sprintf(" (%s)", item.Risk)
				}
			} else if item.IsGhost {
				if item.GhostInfo != "" {
					extra = fmt.Sprintf(" (Ghost: %s)", item.GhostInfo)
				} else {
					extra = " (Ghost)"
				}
			}
		} else if m.scanMode == "RISK" {
			if item.RiskInfo != "" {
				extra = fmt.Sprintf(" (%s)", item.RiskInfo)
			} else if item.Risk != "" && item.Risk != "SAFE" {
				extra = fmt.Sprintf(" (%s)", item.Risk)
			}
		} else if m.scanMode == "GHOST" {
			if item.GhostInfo != "" {
				extra = fmt.Sprintf(" (%s)", item.GhostInfo)
			}
		}
		line := fmt.Sprintf("%s %s [%s] %s%s", cursor, emoji, cleanType, item.ID, extra)
		sb.WriteString(styleFor(item).Render(line) + "\n")
	}
	if len(sortedItems) == 0 {
		sb.WriteString(styleLow.Render("No results found for this scan mode.") + "\n")
	}
	return sb.String()
}

func (m Model) renderFooterContent() string {
	s := ""
	if m.statusMsg != "" {
		if strings.HasPrefix(m.statusMsg, "Error") {
			s += "\n" + styleHigh.Render(m.statusMsg) + "\n"
		} else {
			s += "\n" + styleSafe.Render(m.statusMsg) + "\n"
		}
	}
	total := len(m.resultList)
	timeStr := styleTime.Render(fmt.Sprintf("%s", m.duration.Round(time.Millisecond)))
	s += fmt.Sprintf("\nFound %d resources in %s.", total, timeStr)
	if m.totalCost > 0 {
		moneyStr := styleMoney.Render(fmt.Sprintf("$%.2f/mo", m.totalCost))
		s += fmt.Sprintf("  💰 Est. Cost: %s", moneyStr)
	}
	s += "\n[Up/Down] Navigate  [Enter] Details  [S] Save CSV  [Tab] Switch View  [Esc] Back  [Q] Quit"
	return s
}

func (m Model) renderModal() string {
	r := m.modalItem
	s := modalTitleStyle.Render("RESOURCE DETAILS") + "\n\n"
	s += fmt.Sprintf("ID:   %s\n", r.ID)
	s += fmt.Sprintf("Type: %s\n", r.Type)
	s += fmt.Sprintf("ARN:  %s\n", r.ARN)
	s += "\n"
	if r.Risk != "" && r.Risk != "SAFE" {
		s += styleHigh.Render(fmt.Sprintf("RISK: %s", r.Risk)) + "\n"
		if r.RiskInfo != "" {
			s += fmt.Sprintf("Info: %s\n", r.RiskInfo)
		}
	} else {
		s += styleSafe.Render("RISK: SAFE") + "\n"
	}
	s += "\n"
	if r.IsGhost {
		s += styleMedium.Render("GHOST: YES") + "\n"
		if r.GhostInfo != "" {
			s += fmt.Sprintf("Why:  %s\n", r.GhostInfo)
		}
	} else {
		s += styleLow.Render("GHOST: NO") + "\n"
	}

	s += fmt.Sprintf("Cost: $%.2f/mo\n", r.MonthlyCost)
	s += "\n"
	s += "Tags:\n"
	keys := make([]string, 0, len(r.Tags))
	for k := range r.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s += fmt.Sprintf(" - %s: %s\n", k, r.Tags[k])
	}
	s += "\n" + lipgloss.NewStyle().Foreground(colorGray).Render("[ESC] Close")
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modalStyle.Render(s))
}

func (m Model) View() string {
	if m.showModal {
		return m.renderModal()
	}

	s := ""
	if m.state != StateDone {
		s += lipgloss.NewStyle().Foreground(colorGold).Render(logo) + "\n"
	}
	s += titleStyle.Render("GHOSTSTATE") + "\n"

	switch m.state {
	case StateMenu:
		s += headerStyle.Render(" 1. SELECT TARGETS ") + "\n"
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
			if i == 0 || i == 1 || i == 7 || i == 13 || i == 19 || i == 26 {
				s += sectionStyle.Render(line) + "\n"
			} else {
				s += selectedStyle.Render(line) + "\n"
			}
		}
	case StateConfig:
		s += headerStyle.Render(" 2. AUDIT RULE ") + "\n"
		s += fmt.Sprintf("SCAN MODE: %s (Press 'm' to toggle)\n\n", sectionStyle.Render(m.scanMode))
		for i := range m.inputs {
			s += m.inputs[i].View() + "\n"
		}
		s += lipgloss.NewStyle().Foreground(colorGray).MarginTop(1).Render("[Up/Down/Tab] Navigate Fields   [Enter] Start Scan")
	case StateScan:
		s += headerStyle.Render(" 3. SCANNING... ") + "\n" + m.spinner.View() + "\n"
	case StateDone:
		header := m.renderHeaderContent()
		footer := m.renderFooterContent()

		headerH := strings.Count(header, "\n")
		footerH := strings.Count(footer, "\n")

		availH := m.height - headerH - footerH - 4
		if availH < 5 {
			availH = 5
		}

		fullContent := m.renderListContent()
		lines := strings.Split(fullContent, "\n")

		cursorLineIdx := 0
		for i, line := range lines {
			if strings.Contains(line, ">") && !strings.Contains(line, "Navigate") {
				cursorLineIdx = i
				break
			}
		}

		if cursorLineIdx < m.scrollOffset {
			m.scrollOffset = cursorLineIdx
		}
		if cursorLineIdx >= m.scrollOffset+availH {
			m.scrollOffset = cursorLineIdx - availH + 1
		}

		if m.scrollOffset < 0 {
			m.scrollOffset = 0
		}
		end := m.scrollOffset + availH
		if end > len(lines) {
			end = len(lines)
		}

		if len(lines) < availH {
			m.scrollOffset = 0
			end = len(lines)
		}

		slicedContent := strings.Join(lines[m.scrollOffset:end], "\n")

		padding := ""
		if len(lines) < availH {
			padding = strings.Repeat("\n", availH-len(lines))
		}

		s = header + "\n" + slicedContent + padding + footer
	}
	return s
}
