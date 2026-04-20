package analyzer

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/ghcp-iac/ghcp-iac-workflow/internal/protocol"
)

// refPattern matches Terraform cross-references of the form "azurerm_type.name"
// as they appear in unquoted property values and raw HCL blocks.
// Example: azurerm_subnet.spoke_prod_sub1 (from azurerm_subnet.spoke_prod_sub1.id).
var refPattern = regexp.MustCompile(`\bazurerm_[a-z_]+\.[a-z_][a-z_0-9]*\b`)

// Node is a vertex in the blast-radius dependency graph.
type Node struct {
	// Key is the canonical identifier: "resource_type.resource_name".
	Key string

	// Resource is the underlying parsed IaC resource.
	Resource *protocol.Resource

	// DependsOn holds outgoing edges: resources this node explicitly references.
	DependsOn []*Node

	// DependedBy holds incoming edges: resources that reference this node.
	DependedBy []*Node
}

// Graph is a directed dependency graph built from parsed IaC resources.
type Graph struct {
	nodes map[string]*Node
}

// NewGraph constructs a Graph from a slice of parsed IaC resources.
// Edges are inferred by scanning resource properties and raw HCL blocks for
// Terraform cross-reference patterns (e.g. azurerm_subnet.sub1.id).
func NewGraph(resources []protocol.Resource) *Graph {
	g := &Graph{nodes: make(map[string]*Node, len(resources))}

	// First pass: create all nodes so edge resolution can find any key.
	for i := range resources {
		res := &resources[i]
		key := nodeKey(res.Type, res.Name)
		g.nodes[key] = &Node{Key: key, Resource: res}
	}

	// Second pass: infer edges from cross-references in property values and
	// raw blocks. An edge is created only when the referenced key exists in
	// the graph (same IaC file set).
	for _, node := range g.nodes {
		for _, ref := range extractRefs(node.Resource) {
			if target, ok := g.nodes[ref]; ok && target.Key != node.Key {
				node.DependsOn = appendUnique(node.DependsOn, target)
				target.DependedBy = appendUnique(target.DependedBy, node)
			}
		}
	}

	return g
}

// Node returns the node for the given "type.name" key.
func (g *Graph) Node(key string) (*Node, bool) {
	n, ok := g.nodes[key]
	return n, ok
}

// All returns every node in the graph, sorted by key for deterministic output.
func (g *Graph) All() []*Node {
	result := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		result = append(result, n)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result
}

// Affected returns all nodes impacted when key changes, by following
// DependedBy edges (BFS). The root node itself is not included.
// Use this to answer: "if I change X, what breaks?"
func (g *Graph) Affected(key string) []*Node {
	root, ok := g.nodes[key]
	if !ok {
		return nil
	}
	return bfs(root, func(n *Node) []*Node { return n.DependedBy })
}

// Dependencies returns all nodes reachable from key by following DependsOn
// edges (BFS). The root node itself is not included.
// Use this to answer: "what does X depend on?"
func (g *Graph) Dependencies(key string) []*Node {
	root, ok := g.nodes[key]
	if !ok {
		return nil
	}
	return bfs(root, func(n *Node) []*Node { return n.DependsOn })
}

// GraphAwareScore combines the static resource-type weight with how many
// resources would be affected if this resource changed. The fan-out bonus is
// capped at 10 so a single highly connected resource cannot dominate the score.
func GraphAwareScore(g *Graph, key string) int {
	node, ok := g.nodes[key]
	if !ok {
		return 0
	}
	base := ResourceRiskWeight(node.Resource.Type)
	bonus := len(g.Affected(key))
	if bonus > 10 {
		bonus = 10
	}
	return base + bonus
}

// SeverityFromScore converts a numeric score to a severity band.
//
//	> 20 → Critical
//	> 10 → High
//	>  5 → Medium
//	else → Low
func SeverityFromScore(score int) string {
	switch {
	case score > 20:
		return "Critical"
	case score > 10:
		return "High"
	case score > 5:
		return "Medium"
	default:
		return "Low"
	}
}

// FindHighestImpact returns the key of the node with the greatest
// GraphAwareScore. Returns an empty string if the graph has no nodes.
func FindHighestImpact(g *Graph) string {
	best := ""
	bestScore := -1
	for _, node := range g.All() {
		if s := GraphAwareScore(g, node.Key); s > bestScore {
			bestScore = s
			best = node.Key
		}
	}
	return best
}

// nodeKey returns the canonical "type.name" key for a resource.
func nodeKey(resType, resName string) string {
	return fmt.Sprintf("%s.%s", resType, resName)
}

// bfs performs a breadth-first walk starting from the neighbors of root.
// The root itself is never included in the result.
func bfs(root *Node, neighbors func(*Node) []*Node) []*Node {
	visited := map[string]bool{root.Key: true}
	queue := append([]*Node{}, neighbors(root)...)
	var result []*Node
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if visited[cur.Key] {
			continue
		}
		visited[cur.Key] = true
		result = append(result, cur)
		queue = append(queue, neighbors(cur)...)
	}
	return result
}

// extractRefs returns all "type.name" keys referenced by a resource by scanning
// its raw HCL block and all string-valued properties recursively.
func extractRefs(res *protocol.Resource) []string {
	seen := map[string]bool{}
	var refs []string

	addRef := func(m string) {
		if !seen[m] {
			seen[m] = true
			refs = append(refs, m)
		}
	}

	// Raw block scan catches references that the property parser may flatten.
	for _, m := range refPattern.FindAllString(res.RawBlock, -1) {
		addRef(m)
	}

	// Recursive property scan catches references stored as string values.
	scanProps(res.Properties, addRef)
	return refs
}

// scanProps recursively walks property maps and slices, calling fn for every
// Terraform cross-reference string found.
func scanProps(props map[string]interface{}, fn func(string)) {
	for _, v := range props {
		switch val := v.(type) {
		case string:
			for _, m := range refPattern.FindAllString(val, -1) {
				fn(m)
			}
		case map[string]interface{}:
			scanProps(val, fn)
		case []interface{}:
			for _, item := range val {
				if s, ok := item.(string); ok {
					for _, m := range refPattern.FindAllString(s, -1) {
						fn(m)
					}
				}
			}
		}
	}
}

// appendUnique appends n to slice only if the slice does not already contain it.
func appendUnique(slice []*Node, n *Node) []*Node {
	for _, existing := range slice {
		if existing.Key == n.Key {
			return slice
		}
	}
	return append(slice, n)
}
