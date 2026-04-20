package server

import "github.com/ghcp-iac/ghcp-iac-workflow/internal/protocol"

// AgentRequest represents the incoming request from GitHub Copilot.
// Used for JSON decoding at the HTTP boundary.
type AgentRequest struct {
	Messages []protocol.Message `json:"messages"`
}

// FileAgentRequest allows callers to point the agent at a local IaC file.
// Prompt is optional and can be used to ask a targeted question about the file.
type FileAgentRequest struct {
	Path   string `json:"path"`
	Prompt string `json:"prompt,omitempty"`
}
