package aws

type FoundMsg string
type FinishedMsg struct{}

type ProgressMsg struct {
    Service string
    Status  string
}