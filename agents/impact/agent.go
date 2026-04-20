// Package impact provides the Blast Radius / Impact Analysis agent.
// It runs in two modes:
//   - Targeted: user mentions a specific resource in the prompt → graph traversal
//     from that resource, showing what it depends on and what it affects.
//   - Full-file: no target named → full dependency graph scored across all resources,
//     highlighting the highest-impact node.
package impact

import (
	"context"
	"fmt"
	"strings"

	"github.com/ghcp-iac/ghcp-iac-workflow/internal/analyzer"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/llm"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/parser"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/protocol"
)

// Agent performs graph-based blast-radius analysis of IaC resources.
type Agent struct {
	llmClient *llm.Client
	enableLLM bool
}

// New creates a new impact Agent.
func New(opts ...Option) *Agent {
	a := &Agent{}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Option configures an impact Agent.
type Option func(*Agent)

// WithLLM enables LLM-enhanced impact analysis.
func WithLLM(client *llm.Client) Option {
	return func(a *Agent) {
		a.llmClient = client
		a.enableLLM = client != nil
	}
}

func (a *Agent) ID() string { return "impact" }

func (a *Agent) Metadata() protocol.AgentMetadata {
	return protocol.AgentMetadata{
		ID:          "impact",
		Name:        "Impact Analyzer",
		Description: "Graph-based blast-radius and dependency impact analysis for IaC resources",
		Version:     "2.0.0",
	}
}

func (a *Agent) Capabilities() protocol.AgentCapabilities {
	return protocol.AgentCapabilities{
		Formats:       []protocol.SourceFormat{protocol.FormatTerraform, protocol.FormatBicep},
		NeedsIaCInput: true,
	}
}

// Handle is the main entry point.
// Stage 1 — guard: reject requests with no parsed IaC.
// Stage 2 — build dependency graph from parsed resources.
// Stage 3 — detect targeted resource from the user prompt (if any).
// Stage 4 — run targeted or full-file analysis.
// Stage 5 — optional LLM enrichment.
func (a *Agent) Handle(ctx context.Context, req protocol.AgentRequest, emit protocol.Emitter) error {
	// Stage 1: require IaC input.
	if !protocol.RequireIaC(req, emit, "impact") {
		return nil
	}

	// Stage 2: build the dependency graph.
	g := analyzer.NewGraph(req.IaC.Resources)

	// Stage 3: check if the user named a specific resource to focus on.
	targetKey := detectTargetResource(protocol.PromptText(req), req.IaC.Resources)

	emit.SendMessage("## Blast Radius Analysis\n\n")

	// Stage 4: run the appropriate analysis mode.
	var summaryBuf strings.Builder
	if targetKey != "" {
		a.handleTargeted(g, targetKey, emit, &summaryBuf)
	} else {
		a.handleFullFile(g, req.IaC.Resources, emit, &summaryBuf)
	}

	// Stage 5: optional LLM enrichment with the deterministic summary as context.
	if a.enableLLM && a.llmClient != nil && req.Token != "" {
		a.enhanceWithLLM(ctx, req, summaryBuf.String(), emit)
	}

	return nil
}

// handleTargeted analyzes blast radius starting from one named resource.
// It reports: risk score, what the resource depends on, what would be affected,
// and containment recommendations.
func (a *Agent) handleTargeted(g *analyzer.Graph, key string, emit protocol.Emitter, buf *strings.Builder) {
	node, ok := g.Node(key)
	if !ok {
		emit.SendMessage(fmt.Sprintf("_Resource `%s` not found in the parsed IaC._\n", key))
		return
	}

	score := analyzer.GraphAwareScore(g, key)
	level := analyzer.SeverityFromScore(score)

	line := fmt.Sprintf("### Target: `%s`\n\n**Risk Level: %s** (score: %d)\n\n", key, level, score)
	emit.SendMessage(line)
	buf.WriteString(line)

	// What this resource depends on (outgoing edges).
	emit.SendMessage("#### Dependencies (what this resource needs)\n")
	if len(node.DependsOn) == 0 {
		emit.SendMessage("_No explicit dependencies detected._\n")
	}
	for _, dep := range node.DependsOn {
		depScore := analyzer.GraphAwareScore(g, dep.Key)
		line = fmt.Sprintf("- `%s` — weight: %d\n", dep.Key, depScore)
		emit.SendMessage(line)
		buf.WriteString(line)
	}

	// What would be affected if this resource changes (incoming edges, BFS).
	affected := g.Affected(key)
	emit.SendMessage(fmt.Sprintf("\n#### Blast Radius — resources affected if `%s` changes\n", key))
	if len(affected) == 0 {
		emit.SendMessage("_No downstream dependents detected._\n")
	}
	for _, aff := range affected {
		line = fmt.Sprintf("- `%s` (%s)\n", aff.Key, parser.ShortType(aff.Resource.Type))
		emit.SendMessage(line)
		buf.WriteString(line)
	}

	// Stage 3 (architecture): containment recommendations.
	emit.SendMessage("\n#### Containment Recommendations\n")
	recs := containmentRecommendations(node, affected, level)
	for _, r := range recs {
		emit.SendMessage("- " + r + "\n")
		buf.WriteString("- " + r + "\n")
	}
}

// handleFullFile scores every resource in the graph, identifies the highest-impact
// node, and prints a ranked summary with dependency chain and containment guidance.
func (a *Agent) handleFullFile(g *analyzer.Graph, resources []protocol.Resource, emit protocol.Emitter, buf *strings.Builder) {
	// Score every resource using graph-aware scoring (weight + fan-out bonus).
	type entry struct {
		key   string
		score int
		level string
	}
	var entries []entry
	totalScore := 0
	for _, res := range resources {
		key := fmt.Sprintf("%s.%s", res.Type, res.Name)
		score := analyzer.GraphAwareScore(g, key)
		totalScore += score
		entries = append(entries, entry{key, score, analyzer.SeverityFromScore(score)})
	}

	// Sort by score descending for a ranked output.
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].score > entries[i].score {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	overallLevel := analyzer.SeverityFromScore(totalScore)
	header := fmt.Sprintf("**Overall blast radius score: %d (%s)**\n\n", totalScore, overallLevel)
	emit.SendMessage(header)
	buf.WriteString(header)

	// Ranked resource list.
	emit.SendMessage("#### Resource Impact Scores\n")
	for _, e := range entries {
		line := fmt.Sprintf("- `%s` — score: %d (%s)\n", e.key, e.score, e.level)
		emit.SendMessage(line)
		buf.WriteString(line)
	}

	// Highlight the highest-impact node and its dependency chain.
	hotKey := analyzer.FindHighestImpact(g)
	if hotKey == "" {
		return
	}
	hotNode, _ := g.Node(hotKey)
	affected := g.Affected(hotKey)

	emit.SendMessage(fmt.Sprintf("\n#### Highest-Impact Resource: `%s`\n", hotKey))
	if len(affected) > 0 {
		emit.SendMessage(fmt.Sprintf("Changing `%s` would affect **%d** other resource(s):\n", hotKey, len(affected)))
		for _, aff := range affected {
			line := fmt.Sprintf("- `%s`\n", aff.Key)
			emit.SendMessage(line)
			buf.WriteString(line)
		}
	}

	// Containment recommendations for the hottest node.
	emit.SendMessage("\n#### Containment Recommendations\n")
	recs := containmentRecommendations(hotNode, affected, analyzer.SeverityFromScore(analyzer.GraphAwareScore(g, hotKey)))
	for _, r := range recs {
		emit.SendMessage("- " + r + "\n")
		buf.WriteString("- " + r + "\n")
	}
}

// detectTargetResource scans the user prompt for any resource name that exists
// in the parsed resources, returning its full "type.name" key.
// Prefers longer/more specific matches over shorter ones.
// Returns empty string when no match is found (triggers full-file mode).
func detectTargetResource(prompt string, resources []protocol.Resource) string {
	if prompt == "" {
		return ""
	}
	lower := strings.ToLower(prompt)
	normalized := normalizePrompt(lower)

	type match struct {
		key    string
		score  int  // Higher = better match
		isType bool // Type-based match gets priority
	}

	var bestMatch match

	for _, res := range resources {
		key := fmt.Sprintf("%s.%s", res.Type, res.Name)
		nameLower := strings.ToLower(res.Name)
		keyLower := strings.ToLower(key)
		typeKeyword := extractTypeKeyword(res.Type)

		// Check for full key match (most specific) - score = 1000 + length
		if strings.Contains(lower, keyLower) {
			score := 1000 + len(keyLower)
			if score > bestMatch.score {
				bestMatch = match{key: key, score: score, isType: true}
			}
			continue
		}

		// Check for TYPE keyword match in prompt (e.g., "firewall" matches azurerm_firewall.*)
		// This gets high priority because user is naming the resource TYPE
		if typeKeyword != "" && strings.Contains(normalized, typeKeyword) {
			score := 500 + len(typeKeyword) // Type match priority
			if score > bestMatch.score || (score == bestMatch.score && !bestMatch.isType) {
				bestMatch = match{key: key, score: score, isType: true}
			}
			continue
		}

		// Check for full name match (lower priority than type)
		if strings.Contains(lower, nameLower) {
			score := 100 + len(nameLower)
			if score > bestMatch.score && !bestMatch.isType {
				bestMatch = match{key: key, score: score, isType: false}
			}
			continue
		}

		// Fuzzy match: normalize both and compare
		normalizedName := normalizeResourceName(nameLower)
		if strings.Contains(normalized, normalizedName) && len(normalizedName) > 2 {
			score := 50 + len(normalizedName)
			if score > bestMatch.score && !bestMatch.isType {
				bestMatch = match{key: key, score: score, isType: false}
			}
			continue
		}

		// Partial name match with type hint
		if typeKeyword != "" {
			nameParts := strings.Split(nameLower, "_")
			for _, part := range nameParts {
				if len(part) >= 2 && strings.Contains(normalized, part) {
					score := 30 + len(part)
					if score > bestMatch.score && !bestMatch.isType {
						bestMatch = match{key: key, score: score, isType: false}
					}
					break
				}
			}
		}
	}

	return bestMatch.key
}

// normalizePrompt expands common abbreviations in user input.
func normalizePrompt(prompt string) string {
	// Replace common abbreviations
	replacements := map[string]string{
		"prd":    "prod",
		"stg":    "staging",
		"dev":    "development",
		"fw":     "firewall",
		"vnet":   "virtualnetwork",
		"rg":     "resourcegroup",
		"vm":     "virtualmachine",
		"nic":    "networkinterface",
		"nsg":    "networksecuritygroup",
		"pip":    "publicip",
		"lb":     "loadbalancer",
		"gw":     "gateway",
		"rt":     "routetable",
		"kv":     "keyvault",
		"sa":     "storageaccount",
		"aks":    "kubernetescluster",
		"acr":    "containerregistry",
		"sql":    "database",
		"cosmos": "cosmosdb",
		"snet":   "subnet",
		"sub":    "subnet",
		"peer":   "peering",
	}

	result := strings.ReplaceAll(prompt, "_", " ")
	result = strings.ReplaceAll(result, "-", " ")

	for abbr, full := range replacements {
		// Match whole words only
		result = strings.ReplaceAll(result, " "+abbr+" ", " "+full+" ")
		if strings.HasPrefix(result, abbr+" ") {
			result = full + result[len(abbr):]
		}
		if strings.HasSuffix(result, " "+abbr) {
			result = result[:len(result)-len(abbr)] + full
		}
	}

	return strings.ReplaceAll(result, " ", "")
}

// normalizeResourceName removes underscores and common prefixes.
func normalizeResourceName(name string) string {
	return strings.ReplaceAll(name, "_", "")
}

// extractTypeKeyword returns a simplified keyword for resource type matching.
func extractTypeKeyword(resourceType string) string {
	// Extract the resource-specific part after provider prefix
	parts := strings.Split(resourceType, "_")
	if len(parts) < 2 {
		return ""
	}
	// Skip provider prefix (azurerm, aws, google, etc.)
	return strings.Join(parts[1:], "")
}

// containmentRecommendations returns human-readable mitigation steps based on
// resource type, graph shape, and severity level.
func containmentRecommendations(node *analyzer.Node, affected []*analyzer.Node, level string) []string {
	var recs []string
	t := node.Resource.Type

	switch {
	case strings.Contains(t, "virtual_network_peering"):
		// Peering is the key scenario for the hub-spoke topology.
		recs = append(recs, "Apply peering changes on BOTH hub and spoke sides simultaneously to avoid asymmetric routing.")
		recs = append(recs, "Verify the AD → Firewall → Production path is symmetric after the change.")
		recs = append(recs, "Test authentication flows (Kerberos/LDAP) from prod servers to AD before cutover.")
	case strings.Contains(t, "route_table"):
		recs = append(recs, "Apply route table changes on all associated subnets at the same time to avoid asymmetric paths.")
		recs = append(recs, "Validate return-path routing from the destination subnet before committing.")
	case strings.Contains(t, "firewall"):
		recs = append(recs, "Stage firewall rule changes in a non-production environment first.")
		recs = append(recs, "Keep existing rules active until new rules are verified end-to-end.")
		recs = append(recs, "Ensure SNAT/DNAT rules are consistent with updated UDRs on both sides.")
	case strings.Contains(t, "virtual_network"):
		recs = append(recs, "Apply VNet address-space changes in a maintenance window; all subnets and peerings are affected.")
		recs = append(recs, "Re-validate all peering connections and NSG rules after the change.")
	case strings.Contains(t, "subnet"):
		recs = append(recs, "Drain workloads from this subnet before modifying address prefixes or associations.")
		recs = append(recs, "Validate NSG and route table associations on both sides before cutover.")
	case strings.Contains(t, "linux_virtual_machine"), strings.Contains(t, "virtual_machine"):
		recs = append(recs, "Use availability zones to limit scope; change one VM at a time.")
		recs = append(recs, "Verify AD/DNS connectivity after NIC or subnet changes.")
	case strings.Contains(t, "resource_group"):
		recs = append(recs, "Resource group deletion or move affects ALL child resources — ensure no resources are in use.")
		recs = append(recs, "Take a full backup or snapshot of all critical resources before proceeding.")
	}

	// Generic high-severity recommendations.
	if level == "Critical" || level == "High" {
		recs = append(recs, fmt.Sprintf("Deploy changes in phases (%d resource(s) affected).", len(affected)))
		recs = append(recs, "Define a rollback checkpoint (snapshot / backup) before applying.")
		recs = append(recs, "Limit changes to one availability zone at a time where supported.")
	}

	if len(recs) == 0 {
		recs = append(recs, "No specific containment issues detected for this resource type.")
	}
	return recs
}

const impactPrompt = `You are a senior cloud architect assessing infrastructure change risk.
Given the IaC code and deterministic blast-radius analysis below, provide:
1. A risk assessment explaining what could go wrong if these resources are modified or deleted.
2. Dependency chain analysis — which resources depend on which others.
3. Rollback strategy recommendations.

Be specific. Reference actual resource names. Use markdown. Keep it under 250 words.`

// enhanceWithLLM sends the deterministic summary plus raw IaC to the LLM and
// streams the AI-generated explanation back to the caller.
func (a *Agent) enhanceWithLLM(ctx context.Context, req protocol.AgentRequest, summary string, emit protocol.Emitter) {
	var sb strings.Builder
	sb.WriteString("## IaC Code\n```\n")
	if req.IaC != nil {
		sb.WriteString(req.IaC.RawCode)
	}
	sb.WriteString("\n```\n\n## Deterministic Blast-Radius Summary\n")
	sb.WriteString(summary)

	emit.SendMessage("\n#### AI Impact Assessment\n\n")
	messages := []llm.ChatMessage{{Role: llm.RoleUser, Content: sb.String()}}
	contentCh, errCh := a.llmClient.Stream(ctx, req.Token, impactPrompt, messages)
	for content := range contentCh {
		emit.SendMessage(content)
	}
	if err := <-errCh; err != nil {
		emit.SendMessage(fmt.Sprintf("\n_LLM enhancement unavailable: %v_\n", err))
	}
	emit.SendMessage("\n\n")
}
