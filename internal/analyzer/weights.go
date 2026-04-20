package analyzer

// ResourceRiskWeight returns the risk score for a resource type.
// Higher scores indicate resources with a larger blast radius when modified.
// Unknown types default to 2 — low but non-zero, so they still appear in totals.
func ResourceRiskWeight(resType string) int {
	weights := map[string]int{
		// Compute
		"azurerm_kubernetes_cluster":          8,
		"azurerm_virtual_machine":             5,
		"azurerm_linux_virtual_machine":       5,
		"azurerm_windows_virtual_machine":     5,
		"azurerm_linux_virtual_machine_scale_set": 7,

		// Databases
		"azurerm_mssql_server":    7,
		"azurerm_mssql_database":  6,
		"azurerm_cosmosdb_account": 7,
		"azurerm_mysql_server":    6,
		"azurerm_postgresql_server": 6,

		// Networking — shared infrastructure scores high because many resources depend on it
		"azurerm_resource_group":               8, // parent of everything in the deployment
		"azurerm_virtual_network":              6, // all subnets and peerings depend on it
		"azurerm_subnet":                       4, // VMs, NICs, and endpoints attach here
		"azurerm_virtual_network_peering":      7, // cross-VNet connectivity; must be symmetric
		"azurerm_network_security_group":       5,
		"azurerm_route_table":                  5, // affects routing for every associated subnet
		"azurerm_subnet_route_table_association": 4,
		"azurerm_network_interface":            3,
		"azurerm_public_ip":                    3,
		"azurerm_load_balancer":                6,
		"azurerm_application_gateway":          6,
		"azurerm_private_endpoint":             4,
		"azurerm_dns_zone":                     5,
		"azurerm_dns_a_record":                 3,

		// Security
		"azurerm_firewall":             7, // central traffic inspection; all spoke traffic may route through it
		"azurerm_firewall_policy":      6,
		"azurerm_key_vault":            6,

		// Storage & messaging
		"azurerm_storage_account":   4,
		"azurerm_service_bus_namespace": 5,
		"azurerm_eventhub_namespace":    5,
		"azurerm_redis_cache":           5,

		// Container & app platform
		"azurerm_container_registry": 4,
		"azurerm_service_plan":        3,
		"azurerm_linux_web_app":       4,
		"azurerm_windows_web_app":     4,

		// Observability
		"azurerm_log_analytics_workspace": 4,
		"azurerm_monitor_action_group":    3,
	}
	if w, ok := weights[resType]; ok {
		return w
	}
	return 2
}
