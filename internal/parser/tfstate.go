package parser

import (
	"encoding/json"
	"fmt"

	"github.com/ghcp-iac/ghcp-iac-workflow/internal/protocol"
)

type terraformState struct {
	Resources []terraformStateResource `json:"resources"`
}

type terraformStateResource struct {
	Mode      string                   `json:"mode"`
	Type      string                   `json:"type"`
	Name      string                   `json:"name"`
	Instances []terraformStateInstance `json:"instances"`
}

type terraformStateInstance struct {
	IndexKey   interface{}            `json:"index_key"`
	Attributes map[string]interface{} `json:"attributes"`
}

// ParseTerraformState extracts resources from Terraform tfstate JSON content.
// It maps deployed managed resources into protocol.Resource so agents can
// analyze what is actually deployed, not only what is declared in HCL.
func ParseTerraformState(code string) []protocol.Resource {
	var state terraformState
	if err := json.Unmarshal([]byte(code), &state); err != nil {
		return nil
	}

	resources := make([]protocol.Resource, 0)
	for _, res := range state.Resources {
		if res.Mode != "managed" {
			continue
		}
		if len(res.Instances) == 0 {
			resources = append(resources, protocol.Resource{
				Type:       res.Type,
				Name:       res.Name,
				Properties: map[string]interface{}{},
				Line:       1,
				RawBlock:   "",
			})
			continue
		}

		for _, inst := range res.Instances {
			name := res.Name
			if inst.IndexKey != nil {
				name = fmt.Sprintf("%s[%v]", res.Name, inst.IndexKey)
			}
			props := inst.Attributes
			if props == nil {
				props = map[string]interface{}{}
			}
			resources = append(resources, protocol.Resource{
				Type:       res.Type,
				Name:       name,
				Properties: props,
				Line:       1,
				RawBlock:   "",
			})
		}
	}

	return resources
}