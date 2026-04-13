We want to create a blast radius agent

What this agent is about
-> when we are making any changes we should be able to know what impact could be made by that change - so the agent will let us know where these changes will make impact

-> if I give a resource group, vnet, agent can list down the layers/resources connected to it

Objective:
“Blast radius” = how much of your system gets affected if something goes wrong.

stg1
Impact Analysis
Identifies which resources will be affected
VMs
Resource groups
Applications
Dependencies (network, storage, DB, etc.)

Dependency Mapping
Builds relationships like:
VM → App → Database → Network
Helps understand chain reactions

stg2
Risk Assessment
Classifies impact as:
Low / Medium / High
Based on:
Criticality
Number of dependent systems
Business impact

stg3
Failure Containment
Suggests or enforces:
Do changes in phases
Use availability zones
Limit to subset of servers