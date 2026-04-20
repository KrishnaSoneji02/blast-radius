# Blast Radius Analyzer — User Guide

Analyze the impact of infrastructure changes in Terraform configurations.

---

## Prerequisites

- **Go 1.22+** (for building from source)
- **Local files only**: The `.tf` or `.tfstate` file must be on your local filesystem (no URL/remote support yet)

---

## Getting Started

### Fork & Clone the Repositories

1. **Fork the agent repo** on GitHub
2. **Clone your fork** along with the infrastructure repo:

```powershell
# Clone the blast-radius agent
git clone https://github.com/KrishnaSoneji02/blast-radius.git

# Clone the test infrastructure (provided separately)
git clone https://github.com/<your-username>/infrastructure.git
```

3. **Build the server**:

```powershell
cd blast-radius
go build -o bin/ghcp-iac-server.exe ./cmd/agent-host
```

---

## 🚀 Quick Start

### Step 1: Start the Server

```powershell
cd blast-radius
.\bin\ghcp-iac-server.exe
```

You should see:
```
2026/04/20 15:23:45 LLM enabled: model=gpt-4.1-mini endpoint=https://models.inference.ai.azure.com
2026/04/20 15:23:45 Registered 10 agents, transport=http
2026/04/20 15:23:45 agent-host listening on :8080 (version=dev commit=unknown)
```

### Step 2: Use the Web UI

Open **http://localhost:8080/** in your browser:

![Blast Radius Analyzer UI](docs/screenshots/Main%20interface.png)

*The main interface with File Path input, Prompt field, and example prompt buttons.*

### Step 3: Enter Your Input

1. **File Path**: Enter the full path to your `.tf` or `.tfstate` file  
   Example: `C:\Users\...\infrastructure\terraform.tfstate`

2. **Prompt**: Describe what change you want to analyze  
   Example: `change hub_to_spoke_prod peering`

3. Click one of the **Example prompts** buttons to quickly fill common scenarios

![Input Example](docs/screenshots/Filled%20form.png)

*Analyzing a peering change using the terraform.tfstate file.*

#### Example Prompts

| Prompt | What It Analyzes |
|--------|------------------|
| `delete the firewall` | Impact of removing the firewall |
| `change hub_to_spoke_prod peering` | Impact of modifying the peering connection |
| `modify prod_server VM` | Impact of changing the production VM |
| `routing change in spoke_prod` | Impact of routing changes |
| *(leave empty)* | Full infrastructure analysis |

### Step 4: View Results

Click **Analyze Blast Radius** to see the results:

![Analysis Result](docs/screenshots/Analysis%20result.png)

*Analysis showing Target, Risk Level, Dependencies, Blast Radius, and Containment Recommendations.*

The output shows:
- **Target**: `azurerm_virtual_network_peering.hub_to_spoke_prod` - The resource being analyzed
- **Risk Level**: Medium (score: 7) - Impact severity
- **Dependencies**: What this resource depends on (upstream)
- **Blast Radius**: Resources affected if this changes (downstream)
- **Containment Recommendations**: 
  - Apply peering changes on BOTH hub and spoke sides simultaneously
  - Verify the AD → Firewall → Production path is symmetric
  - Test authentication flows (Kerberos/LDAP) before cutover

---

### Alternative: Command Line

```powershell
$body = @{ 
    path = "C:\path\to\your\main.tf"
    prompt = "delete the firewall" 
} | ConvertTo-Json

Invoke-WebRequest -UseBasicParsing -Method Post `
    -Uri "http://localhost:8080/agent/impact/file?format=text" `
    -ContentType "application/json" `
    -Body $body | Select-Object -ExpandProperty Content
```
