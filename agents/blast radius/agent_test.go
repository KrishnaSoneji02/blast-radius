package blastradius

import (
	"context"
	"strings"
	"testing"

	"github.com/ghcp-iac/ghcp-iac-workflow/internal/host"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/protocol"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/protocol/prototest"
)

// genericNetworkTF: a generic VNet + subnet + storage topology that works for any scenario.
// No AD/Firewall/auth-specific assumptions.
const genericNetworkTF = `
resource "azurerm_virtual_network" "main" {
  name                = "vnet-main"
  location            = "westeurope"
  resource_group_name = "rg-test"
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "app" {
  name                 = "snet-app"
  resource_group_name  = "rg-test"
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "data" {
  name                 = "snet-data"
  resource_group_name  = "rg-test"
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_storage_account" "shared" {
  name                     = "stgshared"
  resource_group_name      = "rg-test"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_mssql_server" "db" {
  name                         = "sqlserver"
  resource_group_name          = "rg-test"
  location                     = "westeurope"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "P@ssw0rd1234"
}

resource "azurerm_linux_virtual_machine" "app_server" {
  name                = "vm-app-01"
  resource_group_name = "rg-test"
  location            = "westeurope"
  size                = "Standard_B2s"
  admin_username      = "azureuser"

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
}
`

// hubSpokeTF: a hub-spoke network topology useful for testing peering and multi-VNet scenarios.
// Still generic enough — no hardcoded AD/auth assumptions.
const hubSpokeTF = `
resource "azurerm_virtual_network" "hub" {
  name                = "vnet-hub"
  location            = "westeurope"
  resource_group_name = "rg-test"
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "hub_shared" {
  name                 = "snet-shared"
  resource_group_name  = "rg-test"
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_virtual_network" "spoke" {
  name                = "vnet-spoke"
  location            = "westeurope"
  resource_group_name = "rg-test"
  address_space       = ["10.1.0.0/16"]
}

resource "azurerm_subnet" "spoke_workload" {
  name                 = "snet-workload"
  resource_group_name  = "rg-test"
  virtual_network_name = azurerm_virtual_network.spoke.name
  address_prefixes     = ["10.1.1.0/24"]
}

resource "azurerm_virtual_network_peering" "hub_to_spoke" {
  name                      = "peer-hub-to-spoke"
  resource_group_name       = "rg-test"
  virtual_network_name      = azurerm_virtual_network.hub.name
  remote_virtual_network_id = azurerm_virtual_network.spoke.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
}

resource "azurerm_virtual_network_peering" "spoke_to_hub" {
  name                      = "peer-spoke-to-hub"
  resource_group_name       = "rg-test"
  virtual_network_name      = azurerm_virtual_network.spoke.name
  remote_virtual_network_id = azurerm_virtual_network.hub.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
}
`

// singleResourceTF: minimal topology for testing a single resource in isolation.
const singleResourceTF = `
resource "azurerm_storage_account" "backup" {
  name                     = "stgbackup"
  resource_group_name      = "rg-test"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
`

// agentRequest wraps tfCode in a fenced HCL block so host.ParseAndEnrich
// can extract and parse it just like a real user prompt would look.
func agentRequest(prompt, tfCode string) protocol.AgentRequest {
	content := prompt + "\n```hcl\n" + tfCode + "\n```"
	req := protocol.AgentRequest{
		Messages: []protocol.Message{
			{Role: "user", Content: content},
		},
	}
	host.ParseAndEnrich(&req)
	return req
}

// TestAgent_ID confirms the agent uses the "blast-radius" registry key.
func TestAgent_ID(t *testing.T) {
	if New().ID() != "blast-radius" {
		t.Error("expected ID = blast-radius")
	}
}

// TestAgent_ImplementsProtocol is a compile-time assertion.
func TestAgent_ImplementsProtocol(t *testing.T) {
	var _ protocol.Agent = (*Agent)(nil)
}

// TestAgent_NoIaC confirms a graceful message when no IaC is provided.
func TestAgent_NoIaC(t *testing.T) {
	a := New()
	rec := &prototest.Recorder{}
	err := a.Handle(context.Background(), protocol.AgentRequest{}, rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(strings.Join(rec.Messages, ""), "No IaC") {
		t.Error("expected no-IaC message")
	}
}

// TestAgent_FullFile_GenericNetwork runs full-file mode on a generic multi-tier topology.
func TestAgent_FullFile_GenericNetwork(t *testing.T) {
	a := New()
	req := agentRequest("blast radius analysis", genericNetworkTF)

	rec := &prototest.Recorder{}
	if err := a.Handle(context.Background(), req, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	combined := strings.Join(rec.Messages, "")

	// Should contain all three stages in full-file mode.
	if !strings.Contains(combined, "Stage 1") {
		t.Error("expected Stage 1 — Resource Impact Scores section")
	}
	if !strings.Contains(combined, "Stage 2") {
		t.Error("expected Stage 2 — Highest-Impact Resource section")
	}
	if !strings.Contains(combined, "Stage 3") {
		t.Error("expected Stage 3 — Containment Recommendations section")
	}
	// Should contain at least one resource type from the topology.
	if !strings.Contains(combined, "storage_account") && !strings.Contains(combined, "mssql_server") {
		t.Error("expected resource types in output")
	}
}

// TestAgent_FullFile_HubSpoke runs full-file mode on hub-spoke topology.
// Verifies the agent handles multi-VNet peering scenarios generically.
func TestAgent_FullFile_HubSpoke(t *testing.T) {
	a := New()
	// No specific resource named → full-file mode.
	req := agentRequest("analyze", hubSpokeTF)

	rec := &prototest.Recorder{}
	if err := a.Handle(context.Background(), req, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	combined := strings.Join(rec.Messages, "")

	// Stage 1: impact list should be present.
	if !strings.Contains(combined, "Stage 1") {
		t.Error("expected Stage 1 — Resource Impact Scores section")
	}
	// Stage 2: highest-impact resource section.
	if !strings.Contains(combined, "Stage 2") {
		t.Error("expected Stage 2 — Highest-Impact Resource section")
	}
	// Stage 3: containment recommendations.
	if !strings.Contains(combined, "Stage 3") {
		t.Error("expected Stage 3 — Containment Recommendations section")
	}
	// VNet peering should be in the output (generic scoring, no scenario assumptions).
	if !strings.Contains(combined, "peering") {
		t.Error("expected peering in output")
	}
}

// TestAgent_Targeted_Network asks about a specific VNet — should trigger targeted mode
// with that VNet as the focus and its dependent subnets in the blast radius.
func TestAgent_Targeted_Network(t *testing.T) {
	a := New()
	req := agentRequest("what happens if I change the main vnet", genericNetworkTF)

	rec := &prototest.Recorder{}
	if err := a.Handle(context.Background(), req, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	combined := strings.Join(rec.Messages, "")

	// Targeted section header should appear.
	if !strings.Contains(combined, "Target:") {
		t.Error("expected targeted mode header")
	}
	// Subnets that depend on the VNet should appear in blast radius.
	if !strings.Contains(combined, "app") && !strings.Contains(combined, "data") {
		t.Error("expected dependent subnets in blast radius")
	}
}

// TestAgent_Targeted_Peering asks about peering specifically in hub-spoke topology.
// Should detect peering as the target and show generic containment advice.
func TestAgent_Targeted_Peering(t *testing.T) {
	a := New()
	// "peering" in the prompt should match the peering resources.
	req := agentRequest("blast radius of the peering?", hubSpokeTF)

	rec := &prototest.Recorder{}
	if err := a.Handle(context.Background(), req, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	combined := strings.Join(rec.Messages, "")

	// Should enter targeted mode.
	if !strings.Contains(combined, "Target:") {
		t.Error("expected targeted mode with peering as target")
	}
	// Containment must mention connectivity and validation (generic).
	if !strings.Contains(combined, "connectivity") && !strings.Contains(combined, "validate") {
		t.Error("expected generic connectivity/validation containment advice")
	}
}

// TestAgent_Targeted_SingleResource asks about a storage account with no dependencies.
// Should show it as a leaf resource with minimal blast radius.
func TestAgent_Targeted_SingleResource(t *testing.T) {
	a := New()
	req := agentRequest("what if I delete the backup storage account", singleResourceTF)

	rec := &prototest.Recorder{}
	if err := a.Handle(context.Background(), req, rec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	combined := strings.Join(rec.Messages, "")

	// Targeted section.
	if !strings.Contains(combined, "Target:") {
		t.Error("expected targeted mode")
	}
	// Storage account should be in output.
	if !strings.Contains(combined, "backup") && !strings.Contains(combined, "storage") {
		t.Error("expected storage account in targeted analysis")
	}
}

// TestAgent_SeverityBands_Generic verifies severity classification works across
// different topologies and resource combinations.
func TestAgent_SeverityBands_Generic(t *testing.T) {
	a := New()
	tests := []struct {
		name   string
		code   string
		expect string // one of Low, Medium, High, Critical
	}{
		{
			name:   "single_storage",
			code:   singleResourceTF,
			expect: "Low", // one isolated resource
		},
		{
			name:   "hub_spoke",
			code:   hubSpokeTF,
			expect: "High", // multiple VNets + peering + subnets
		},
		{
			name:   "multi_tier",
			code:   genericNetworkTF,
			expect: "High", // VNets + subnets + storage + database + VM
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := agentRequest("analyze", tt.code)
			rec := &prototest.Recorder{}
			if err := a.Handle(context.Background(), req, rec); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			combined := strings.Join(rec.Messages, "")
			if !strings.Contains(combined, tt.expect) {
				t.Errorf("expected severity %s but got: %q (partial)", tt.expect, combined[:200])
			}
		})
	}
}

// TestAgent_GenericContainmentAdvice verifies that containment recommendations
// are generic and work across different resource types and topologies.
// Peering, VNets, storage, and databases should all get type-appropriate
// but scenario-agnostic advice.
func TestAgent_GenericContainmentAdvice(t *testing.T) {
	a := New()
	tests := []struct {
		name         string
		code         string
		target       string // name to match in the prompt
		shouldContain string // generic advice that should appear
	}{
		{
			name:         "peering_advice",
			code:         hubSpokeTF,
			target:       "peering",
			shouldContain: "symmetric", // containment should mention symmetric paths
		},
		{
			name:         "storage_advice",
			code:         genericNetworkTF,
			target:       "shared",    // storage account name
			shouldContain: "access",   // containment should mention access/keys
		},
		{
			name:         "database_advice",
			code:         genericNetworkTF,
			target:       "database", // generic word to match database
			shouldContain: "dependent", // should mention dependent resources
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := agentRequest("what if I change "+tt.target, tt.code)
			rec := &prototest.Recorder{}
			if err := a.Handle(context.Background(), req, rec); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			combined := strings.Join(rec.Messages, "")

			// Should have containment recommendations.
			if !strings.Contains(combined, "Stage 3") {
				t.Fatal("expected Stage 3 containment section")
			}
			// Generic advice should be present (not scenario-specific).
			if !strings.Contains(combined, tt.shouldContain) {
				t.Errorf("expected %q in advice (not scenario-specific), got: %q", tt.shouldContain, combined[:300])
			}
		})
	}
}
