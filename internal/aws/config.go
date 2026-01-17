package aws

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/K0NGR3SS/GhostState/internal/scanner"
)

type FoundMsg string
type FinishedMsg struct{}

type AuditMode string

const (
	ModeMissingSpecificTag AuditMode = "MISSING_SPECIFIC_TAG"
	ModeNoTags             AuditMode = "NO_TAGS"
)

type AuditConfig struct {
	ScanEC2       bool
	ScanS3        bool
	ScanLambda    bool
	ScanRDS       bool
	ScanElasti    bool
	ScanDynamoDB  bool
	ScanACM       bool
	ScanSecGroups bool
	ScanVPC       bool
	ScanECS       bool
	ScanCloudfront bool

	Mode      AuditMode
	TargetKey string
	TargetVal string
}

func send(p *tea.Program, s string) {
	if p != nil {
		p.Send(FoundMsg(s))
	}
}

func runScan(p *tea.Program, s scanner.Scanner, conf AuditConfig) {
	rule := scanner.AuditRule{TargetKey: conf.TargetKey, TargetVal: conf.TargetVal}
	res, err := s.Scan(context.TODO(), rule)
	if err != nil {
		send(p, "Scan Error: "+err.Error())
		return
	}
	for _, r := range res {
		send(p, fmt.Sprintf("%s: %s", r.Type, r.ID))
	}
}
