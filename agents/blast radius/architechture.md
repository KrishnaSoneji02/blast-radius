# Impact Agent Architecture

## Purpose

This document explains:
- what the existing `impact` agent does today
- what gaps exist compared to the desired blast-radius behavior
- what architecture should be added to evolve it safely

The goal is to deepen the current `impact` agent into a true blast-radius analyzer without introducing a separate agent ID in v1.

## Current State

### Registered flow
- The host registers the `impact` agent in `cmd/agent-host/main.go`.
- The orchestrator includes `impact` in the default analyze workflow.
- Requests are parsed by `host.ParseAndEnrich()` into `protocol.IaCInput` before the agent runs.

### What the current impact agent actually does
The current implementation in `agents/impact/agent.go`:
- requires IaC input
- emits a `Blast Radius` heading
- loops through parsed resources
- looks up a static risk weight per resource type using `analyzer.ResourceRiskWeight()`
- sums all weights into one total score
- classifies the total as `Low`, `Medium`, `High`, or `Critical`
- optionally asks the LLM to explain risk, dependencies, and rollback ideas

### What it does not do
The current implementation does not:
- build relationships between resources
- identify upstream or downstream dependencies
- answer targeted questions about one resource such as a VNet or resource group
- trace chain reactions
- distinguish isolated resources from central shared resources
- model containment strategies based on actual dependency topology

### Current scoring model
The current score is based only on static resource-type weights.
Examples from `internal/analyzer/weights.go`:
- AKS cluster: 8
- SQL server: 7
- Storage account: 4
- Virtual network: 3
- Unknown resource types default to 2

This means the current result is a resource inventory risk sum, not a true blast-radius analysis.

## Desired State

The desired blast-radius behavior from the decision note is:
- identify what resources are affected by a change or failure
- map dependencies between resources
- answer questions starting from a chosen resource
- classify impact based on dependency scope and criticality
- suggest failure containment and phased change guidance

## Recommended Architecture

### 1. Keep the existing `impact` agent ID
Reason:
- avoids changes to registration and routing contracts
- keeps orchestrator behavior stable
- minimizes migration risk for any caller already using `impact`

### 2. Add a deterministic dependency graph core
The core of the new design should be a graph built from parsed IaC resources.

Graph model:
- node: one `protocol.Resource`
- edge: one inferred dependency relationship between two resources

Primary deterministic signals:
- known reference properties such as IDs, names, subnet links, storage references, service plan references, server references, and network references
- raw block cross-references when parsed property maps are too shallow
- resource-group membership and known Azure parent-child patterns

The deterministic graph should be the system of record for v1.

### 3. Support two analysis modes inside the same agent
Mode A: full-file blast radius
- analyze all parsed resources
- find high-risk connected components
- summarize broad shared-resource impact

Mode B: targeted-resource blast radius
- detect a resource named in the user prompt
- start traversal from that resource
- list directly and indirectly affected resources
- explain upstream and downstream impact

### 4. Evolve scoring from flat weight sum to graph-aware severity
Severity should combine:
- base resource risk weight
- number of dependents
- dependency depth
- whether the resource is shared infrastructure such as network, database, cluster, or storage

Suggested interpretation:
- Low: isolated or low-fan-out impact
- Medium: limited connected resources or moderate shared use
- High: broad dependency fan-out or important shared platform component
- Critical: central shared infrastructure with large downstream effect

### 5. Make containment recommendations part of the output
Containment output should be based on graph shape and resource type.
Examples:
- phase changes through subsets of servers or workloads
- isolate by zone or environment
- stage network changes before compute changes
- define rollback checkpoints before modifying shared dependencies

### 6. Use LLM only as a bounded secondary layer
Recommended hybrid model:
- deterministic engine finds nodes, edges, paths, and primary score
- LLM explains likely chain reactions in clearer language
- LLM proposes extra containment guidance for cases not fully covered by deterministic rules

The LLM should not replace deterministic graph inference when the code already provides a confident answer.

## Proposed Internal Structure

### In `agents/impact`
Keep the public agent contract unchanged, but internally split behavior into stages:
1. request interpretation
2. target resource matching
3. dependency graph construction
4. graph traversal and severity scoring
5. containment recommendation generation
6. optional LLM enhancement

### Data used from existing code
Reuse existing inputs instead of adding new request schema in v1:
- `protocol.AgentRequest`
- `protocol.IaCInput`
- `protocol.Resource`
- parsed `Properties`
- `RawBlock`
- `analyzer.ResourceRiskWeight()`

### Files most relevant to the design
- `agents/impact/agent.go`
- `agents/impact/agent_test.go`
- `agents/orchestrator/agent.go`
- `cmd/agent-host/main.go`
- `internal/protocol/types.go`
- `internal/parser/terraform.go`
- `internal/parser/bicep.go`
- `internal/analyzer/weights.go`

## Expected Output Shape

A stronger impact-agent response should include:
- blast-radius summary
- selected resource or scope analyzed
- connected resources and dependency chain
- severity level with reason
- containment recommendations
- optional AI explanation when enabled

Example sections:
- `Blast Radius Summary`
- `Connected Resources`
- `Dependency Chain`
- `Risk Level`
- `Containment Recommendations`

## Non-Goals For V1

The first version should not depend on:
- live Azure inventory or runtime APIs
- historical deployment state
- diffing previous and current infrastructure revisions
- business metadata not present in IaC
- a new registered `blastradius` agent

## Summary

Today, the `impact` agent is a static weighted resource summary with optional LLM commentary.

The architecture we are adding turns it into a graph-based blast-radius analyzer that can:
- answer targeted dependency questions
- show which resources are connected
- estimate chain-reaction scope
- provide containment guidance

This preserves the current agent contract while adding the missing analysis depth needed for real blast-radius behavior.