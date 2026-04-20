// Package blastradius is the blast-radius agent implementation.
//
// This package lives in the "agents/blast radius/" directory (space in path).
// Because Go import paths cannot contain spaces it is not registered in
// cmd/agent-host/main.go; the equivalent registered agent is "impact"
// (agents/impact/agent.go), which contains the same graph-based logic.
// This package serves as the canonical reference implementation and can be
// exercised independently via:
//
//	go test ./agents/blast\ radius/
//
// Architecture (three stages from decision.md):
//
//	Stage 1 — Impact Analysis  : identify affected resources via dependency graph
//	Stage 2 — Risk Assessment  : GraphAwareScore → Low / Medium / High / Critical
//	Stage 3 — Failure Containment: per-resource containment recommendations
package blastradius

import (
	"context"
	"fmt"
	"strings"

	"github.com/ghcp-iac/ghcp-iac-workflow/internal/analyzer"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/llm"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/parser"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/protocol"
)

// Agent implements graph-based blast-radius analysis across all three stages
// defined in decision.md: impact analysis, risk assessment, and failure containment.
type Agent struct {
	llmClient *llm.Client
	enableLLM bool
}

// Option configures an Agent.
type Option func(*Agent)

// WithLLM attaches an LLM client for AI-enhanced explanations.
func WithLLM(client *llm.Client) Option {
	return func(a *Agent) {
		a.llmClient = client
		a.enableLLM = client != nil
	}
}

// New creates a blast-radius Agent.
func New(opts ...Option) *Agent {
	a := &Agent{}
	for _, o := range opts {
		o(a)
	}
	return a
}

// ID returns the unique agent identifier used by the dispatcher/registry.
func (a *Agent) ID() string { return "blast-radius" }

// Metadata describes the agent for registry listing and discovery.
func (a *Agent) Metadata() protocol.AgentMetadata {
	return protocol.AgentMetadata{
		ID:          "blast-radius",
		Name:        "Blast Radius Analyzer",
		Description: "Three-stage blast-radius analysis: impact mapping, risk scoring, and failure containment",
		Version:     "1.0.0",
	}
}

// Capabilities declares that this agent needs IaC input and supports Terraform and Bicep.
func (a *Agent) Capabilities() protocol.AgentCapabilities {
	return protocol.AgentCapabilities{
		Formats:       []protocol.SourceFormat{protocol.FormatTerraform, protocol.FormatBicep},
		NeedsIaCInput: true,
	}
}

// Handle runs the three-stage blast-radius pipeline.
//
// Stage 1 — Impact Analysis:
//   - Build a dependency graph from parsed IaC resources.
//   - Detect if the user named a specific resource (targeted mode).
//   - Map which resources would be affected using graph BFS traversal.
//
// Stage 2 — Risk Assessment:
//   - Compute GraphAwareScore (static weight + fan-out bonus) per resource.
//   - Classify as Low / Medium / High / Critical.
//
// Stage 3 — Failure Containment:
//   - Emit per-resource containment recommendations based on type and severity.
func (a *Agent) Handle(ctx context.Context, req protocol.AgentRequest, emit protocol.Emitter) error {
	// Require IaC input; reject gracefully if absent.
	if !protocol.RequireIaC(req, emit, "blast-radius") {
		return nil
	}

	// ── Stage 1: Impact Analysis ─────────────────────────────────────────────

	// Build dependency graph: nodes = resources, edges = Terraform cross-references.
	g := analyzer.NewGraph(req.IaC.Resources)

	// Detect whether the user asked about one specific resource.
	targetKey := detectTarget(protocol.PromptText(req), req.IaC.Resources)

	emit.SendMessage("## Blast Radius Analysis\n\n")
	var summaryBuf strings.Builder

	if targetKey != "" {
		// Targeted mode: user asked about a specific resource.
		a.stageImpactTargeted(g, targetKey, emit, &summaryBuf)
	} else {
		// Full-file mode: score and rank every resource in the topology.
		a.stageImpactFullFile(g, req.IaC.Resources, emit, &summaryBuf)
	}

	// Optional LLM layer: AI explanation on top of the deterministic output.
	if a.enableLLM && a.llmClient != nil && req.Token != "" {
		a.stageEnhanceLLM(ctx, req, summaryBuf.String(), emit)
	}

	return nil
}

// ── Stage 1 helpers ───────────────────────────────────────────────────────────

// stageImpactTargeted runs targeted blast-radius analysis from one resource.
// It maps dependencies (what the resource needs) and the blast radius (what
// breaks when this resource changes), then hands off to stage 2 for scoring
// and stage 3 for containment.
func (a *Agent) stageImpactTargeted(g *analyzer.Graph, key string, emit protocol.Emitter, buf *strings.Builder) {
	node, ok := g.Node(key)
	if !ok {
		emit.SendMessage(fmt.Sprintf("_Resource `%s` not found in the parsed IaC._\n", key))
		return
	}

	// ── Stage 2: Risk Assessment for the target ───────────────────────────────
	score := analyzer.GraphAwareScore(g, key)
	level := analyzer.SeverityFromScore(score)

	header := fmt.Sprintf("### Target: `%s`\n\n**Risk Level: %s** (score: %d)\n\n", key, level, score)
	emit.SendMessage(header)
	buf.WriteString(header)

	// Dependency Mapping: what does this resource need?
	emit.SendMessage("#### Stage 1a — Dependency Map (what this resource needs)\n")
	deps := g.Dependencies(key)
	if len(deps) == 0 {
		emit.SendMessage("_No explicit upstream dependencies detected._\n")
	}
	for _, dep := range deps {
		depScore := analyzer.GraphAwareScore(g, dep.Key)
		line := fmt.Sprintf("- `%s` — score: %d (%s)\n", dep.Key, depScore, analyzer.SeverityFromScore(depScore))
		emit.SendMessage(line)
		buf.WriteString(line)
	}

	// Blast radius: which resources are affected if this one changes?
	affected := g.Affected(key)
	subheader := fmt.Sprintf("\n#### Stage 1b — Blast Radius (resources affected if `%s` changes)\n", key)
	emit.SendMessage(subheader)
	buf.WriteString(subheader)
	if len(affected) == 0 {
		emit.SendMessage("_No downstream dependents detected — this resource is a leaf node._\n")
	}
	for _, aff := range affected {
		line := fmt.Sprintf("- `%s` (%s)\n", aff.Key, parser.ShortType(aff.Resource.Type))
		emit.SendMessage(line)
		buf.WriteString(line)
	}

	// ── Stage 3: Failure Containment ─────────────────────────────────────────
	emit.SendMessage("\n#### Stage 3 — Containment Recommendations\n")
	for _, rec := range containmentRecs(node, affected, level) {
		r := "- " + rec + "\n"
		emit.SendMessage(r)
		buf.WriteString(r)
	}
}

// stageImpactFullFile scores every resource in the graph and highlights the
// highest-impact node with its full dependency chain and containment advice.
func (a *Agent) stageImpactFullFile(g *analyzer.Graph, resources []protocol.Resource, emit protocol.Emitter, buf *strings.Builder) {
	type entry struct {
		key   string
		score int
	}
	entries := make([]entry, 0, len(resources))
	totalScore := 0
	for _, res := range resources {
		key := fmt.Sprintf("%s.%s", res.Type, res.Name)
		score := analyzer.GraphAwareScore(g, key)
		totalScore += score
		entries = append(entries, entry{key, score})
	}

	// Sort descending by score.
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].score > entries[i].score {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	overallLevel := analyzer.SeverityFromScore(totalScore)
	header := fmt.Sprintf("**Overall blast-radius score: %d (%s)**\n\n", totalScore, overallLevel)
	emit.SendMessage(header)
	buf.WriteString(header)

	// ── Stage 1a: full ranked impact list ────────────────────────────────────
	emit.SendMessage("#### Stage 1 — Resource Impact Scores\n")
	for _, e := range entries {
		line := fmt.Sprintf("- `%s` — score: %d (%s)\n", e.key, e.score, analyzer.SeverityFromScore(e.score))
		emit.SendMessage(line)
		buf.WriteString(line)
	}

	// ── Stage 2: highlight the hottest node ──────────────────────────────────
	hotKey := analyzer.FindHighestImpact(g)
	if hotKey == "" {
		return
	}
	hotNode, _ := g.Node(hotKey)
	affected := g.Affected(hotKey)
	hotScore := analyzer.GraphAwareScore(g, hotKey)
	hotLevel := analyzer.SeverityFromScore(hotScore)

	subheader := fmt.Sprintf("\n#### Stage 2 — Highest-Impact Resource: `%s` (%s)\n", hotKey, hotLevel)
	emit.SendMessage(subheader)
	buf.WriteString(subheader)

	if len(affected) > 0 {
		emit.SendMessage(fmt.Sprintf("Changing `%s` would affect **%d** other resource(s):\n", hotKey, len(affected)))
		for _, aff := range affected {
			line := fmt.Sprintf("- `%s`\n", aff.Key)
			emit.SendMessage(line)
			buf.WriteString(line)
		}
	} else {
		emit.SendMessage("_This resource has no downstream dependents._\n")
	}

	// ── Stage 3: containment for the hottest node ─────────────────────────────
	emit.SendMessage("\n#### Stage 3 — Containment Recommendations\n")
	for _, rec := range containmentRecs(hotNode, affected, hotLevel) {
		r := "- " + rec + "\n"
		emit.SendMessage(r)
		buf.WriteString(r)
	}
}

// ── Stage 2 helpers ───────────────────────────────────────────────────────────

// detectTarget scans the user prompt for any resource name matching parsed
// resources and returns the full "type.name" key on first match.
// Returns empty string when no match is found → full-file mode is used.
func detectTarget(prompt string, resources []protocol.Resource) string {
	if prompt == "" {
		return ""
	}
	lower := strings.ToLower(prompt)
	for _, res := range resources {
		key := fmt.Sprintf("%s.%s", res.Type, res.Name)
		if strings.Contains(lower, strings.ToLower(res.Name)) ||
			strings.Contains(lower, strings.ToLower(key)) {
			return key
		}
	}
	return ""
}

// ── Stage 3 helpers ───────────────────────────────────────────────────────────

// containmentRecs returns generic, topology-agnostic mitigation steps tailored to
// resource type, dependency scope, and severity level. Recommendations are based on
// general cloud-infrastructure best practices and do not assume a specific topology.
func containmentRecs(node *analyzer.Node, affected []*analyzer.Node, level string) []string {
	var recs []string
	t := node.Resource.Type
	affectedCount := len(affected)

	// Type-based recommendations: critical coordination patterns and constraints.
	switch {
	case strings.Contains(t, "virtual_network_peering"):
		// Peering is bidirectional and affects traffic symmetry between networks.
		recs = append(recs,
			"Apply peering changes and corresponding cross-network routes on both VNets to ensure symmetric connectivity.",
			"Validate bidirectional traffic flow after the change; test both directions independently.",
			"Plan for transient connectivity loss between peered networks during the change.",
		)
	case strings.Contains(t, "route_table"):
		// Route table changes affect all subnets using that table.
		recs = append(recs,
			fmt.Sprintf("This route table is used by %d resource(s); changes affect all of them.", affectedCount),
			"Validate return-path routing and confirm upstream routers accept return traffic.",
			"Test traffic flow end-to-end before removing old routes.",
		)
	case strings.Contains(t, "firewall") || strings.Contains(t, "network_security_group"):
		// Network policy changes can break traffic unexpectedly.
		recs = append(recs,
			"Stage rule changes in a non-production environment first.",
			"Keep old rules active until new rules are verified end-to-end; avoid rule gaps.",
			"Test connectivity from all known client subnets before cutover.",
		)
	case strings.Contains(t, "virtual_network"):
		// VNet changes cascade to all subnets and peerings.
		recs = append(recs,
			fmt.Sprintf("VNet changes affect %d dependent resource(s); schedule a maintenance window.", affectedCount),
			"Re-validate all peering connections, NSG rules, and route tables after address-space changes.",
		)
	case strings.Contains(t, "subnet"):
		// Subnet changes affect running workloads and route propagation.
		recs = append(recs,
			fmt.Sprintf("This subnet impacts %d resource(s); drain or migrate workloads before address-space changes.", affectedCount),
			"Verify NSG and route-table associations propagate correctly after changes.",
		)
	case strings.Contains(t, "linux_virtual_machine") || strings.Contains(t, "windows_virtual_machine") || strings.Contains(t, "virtual_machine"):
		// VM changes can impact dependent services and load balancers.
		recs = append(recs,
			fmt.Sprintf("Changing this VM impacts %d dependent resource(s); use phased deployment.", affectedCount),
			"Update or drain connected load balancers and service dependencies before VM changes.",
			"Verify network connectivity and service dependencies after VM scale or NIC changes.",
		)
	case strings.Contains(t, "database") || strings.Contains(t, "sql_server") || strings.Contains(t, "cosmosdb"):
		// Database changes can break dependent applications.
		recs = append(recs,
			fmt.Sprintf("This database is used by %d dependent application(s); coordinate downtime or failover.", affectedCount),
			"Test connection strings and failover paths before production changes.",
		)
	case strings.Contains(t, "storage_account"):
		// Storage changes affect all dependent compute resources.
		recs = append(recs,
			fmt.Sprintf("This storage account is used by %d resource(s); ensure all clients buffer data before changes.", affectedCount),
			"Verify access keys and SAS tokens are distributed to all clients after regeneration.",
		)
	case strings.Contains(t, "resource_group"):
		// Resource group operations cascade to all children.
		recs = append(recs,
			fmt.Sprintf("Resource group operations affect ALL %d child resource(s).", affectedCount),
			"Ensure no critical workloads are running in the group before deletion or move.",
		)
	}

	// Severity-based general recommendations.
	if level == "Critical" {
		recs = append(recs,
			fmt.Sprintf("CRITICAL: This change impacts %d other resource(s). Execute in a maintenance window with team oversight.", affectedCount),
			"Create a full backup or snapshot of all impacted resources before proceeding.",
			"Define rollback steps explicitly and verify they can be executed in < 30 minutes.",
			"Have a communication plan in place for potential downtime.",
		)
	} else if level == "High" {
		recs = append(recs,
			fmt.Sprintf("HIGH IMPACT: Deploy changes in phases (%d resource(s) affected).", affectedCount),
			"Define rollback checkpoints (snapshots, backups, or blue-green deployments) before proceeding.",
			"Limit change scope to one subnet, zone, or service at a time where possible.",
		)
	} else if level == "Medium" && affectedCount > 3 {
		recs = append(recs,
			fmt.Sprintf("MULTIPLE IMPACTS: This change affects %d resource(s). Test in a controlled environment first.", affectedCount),
			"Plan for sequential deployment to catch issues early.",
		)
	}

	if len(recs) == 0 {
		recs = append(recs, "This is a low-impact change with no detected dependent resources.")
	}
	return recs
}

const blastRadiusPrompt = `You are a senior cloud architect assessing infrastructure change risk.
Given the IaC code and the deterministic blast-radius analysis below, provide:
1. A risk assessment for what could go wrong if these resources are modified or deleted.
2. Dependency chain narrative — explain the chain reaction in plain language.
3. Rollback strategy with concrete steps.

Be specific. Reference actual resource names. Use markdown. Keep it under 250 words.`

// stageEnhanceLLM sends the deterministic analysis summary plus the raw IaC to
// the LLM and streams the AI-generated explanation back.
func (a *Agent) stageEnhanceLLM(ctx context.Context, req protocol.AgentRequest, summary string, emit protocol.Emitter) {
	var sb strings.Builder
	sb.WriteString("## IaC Code\n```\n")
	if req.IaC != nil {
		sb.WriteString(req.IaC.RawCode)
	}
	sb.WriteString("\n```\n\n## Deterministic Blast-Radius Analysis\n")
	sb.WriteString(summary)

	emit.SendMessage("\n#### AI-Enhanced Explanation\n\n")
	messages := []llm.ChatMessage{{Role: llm.RoleUser, Content: sb.String()}}
	contentCh, errCh := a.llmClient.Stream(ctx, req.Token, blastRadiusPrompt, messages)
	for content := range contentCh {
		emit.SendMessage(content)
	}
	if err := <-errCh; err != nil {
		emit.SendMessage(fmt.Sprintf("\n_LLM enhancement unavailable: %v_\n", err))
	}
	emit.SendMessage("\n\n")
}
