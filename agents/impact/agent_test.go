package impact

import (
	"context"
	"strings"
	"testing"

	"github.com/ghcp-iac/ghcp-iac-workflow/internal/host"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/protocol"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/protocol/prototest"
)

// Verifies the agent exposes the stable registry ID used by the host.
func TestAgent_ID(t *testing.T) {
	if New().ID() != "impact" {
		t.Error("expected ID = impact")
	}
}

// Exercises the normal flow: parse IaC from the user message, run the agent,
// then assert that the emitted summary includes a scored blast radius.
func TestAgent_BlastRadius(t *testing.T) {
	a := New()
	tfCode := `resource "azurerm_kubernetes_cluster" "aks" {
  name                = "myaks"
  location            = "eastus"
  resource_group_name = "rg"
  dns_prefix          = "myaks"
}

resource "azurerm_storage_account" "store" {
  name                     = "mystore"
  resource_group_name      = "rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}`
	// The host populates req.IaC by extracting the fenced Terraform snippet.
	req := protocol.AgentRequest{
		Messages: []protocol.Message{
			{Role: "user", Content: "impact:\n```hcl\n" + tfCode + "\n```"},
		},
	}
	host.ParseAndEnrich(&req)
	// Recorder captures the streaming emitter output so the test can assert on it.
	rec := &prototest.Recorder{}
	err := a.Handle(context.Background(), req, rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	combined := strings.Join(rec.Messages, "")
	if !strings.Contains(combined, "Blast Radius") {
		t.Error("expected Blast Radius header")
	}
	if !strings.Contains(combined, "risk weight") {
		t.Error("expected risk weight in output")
	}
	// AKS(8) + storage(4) = 12 -> High
	if !strings.Contains(combined, "High") {
		t.Error("expected High blast radius for AKS + storage")
	}
}

// Confirms the agent fails gracefully when no Terraform or Bicep input is present.
func TestAgent_NoIaC(t *testing.T) {
	a := New()
	rec := &prototest.Recorder{}
	err := a.Handle(context.Background(), protocol.AgentRequest{}, rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	combined := strings.Join(rec.Messages, "")
	if !strings.Contains(combined, "No IaC") {
		t.Error("expected no-IaC message")
	}
}

// Compile-time check that the concrete type still satisfies the shared interface.
func TestAgent_ImplementsAgent(t *testing.T) {
	var _ protocol.Agent = (*Agent)(nil)
}
