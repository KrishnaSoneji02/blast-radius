// Command agent-host is the new entry point for the IaC governance agent.
// It registers all agents, sets up the orchestrator as the default handler,
// and supports both HTTP (SSE) and MCP stdio transports.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ghcp-iac/ghcp-iac-workflow/agents/compliance"
	"github.com/ghcp-iac/ghcp-iac-workflow/agents/cost"
	"github.com/ghcp-iac/ghcp-iac-workflow/agents/deploy"
	"github.com/ghcp-iac/ghcp-iac-workflow/agents/drift"
	"github.com/ghcp-iac/ghcp-iac-workflow/agents/impact"
	"github.com/ghcp-iac/ghcp-iac-workflow/agents/module"
	"github.com/ghcp-iac/ghcp-iac-workflow/agents/notification"
	"github.com/ghcp-iac/ghcp-iac-workflow/agents/orchestrator"
	"github.com/ghcp-iac/ghcp-iac-workflow/agents/policy"
	"github.com/ghcp-iac/ghcp-iac-workflow/agents/security"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/auth"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/config"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/host"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/llm"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/protocol"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/server"
	"github.com/ghcp-iac/ghcp-iac-workflow/internal/transport/mcpstdio"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	transport := flag.String("transport", "http", "Transport mode: http or stdio")
	flag.Parse()

	cfg := config.Load()

	// Create LLM client if enabled
	var llmClient *llm.Client
	if cfg.EnableLLM {
		llmClient = llm.NewClient(cfg.ModelEndpoint, cfg.ModelName, cfg.ModelMaxTokens, cfg.ModelTimeout)
		log.Printf("LLM enabled: model=%s endpoint=%s", cfg.ModelName, cfg.ModelEndpoint)
	}

	// Build registry
	registry := host.NewRegistry()

	registry.Register(policy.New(policy.WithLLM(llmClient)))
	registry.Register(security.New(security.WithLLM(llmClient)))
	registry.Register(compliance.New(compliance.WithLLM(llmClient)))
	registry.Register(cost.New(cost.WithLLM(llmClient)))
	registry.Register(drift.New())
	registry.Register(deploy.New())
	registry.Register(notification.New(cfg.EnableNotifications))
	registry.Register(impact.New(impact.WithLLM(llmClient)))
	registry.Register(module.New())

	// Orchestrator uses registry lookup
	orch := orchestrator.New(func(id string) (protocol.Agent, bool) {
		return registry.Get(id)
	}, orchestrator.WithLLM(llmClient))
	registry.Register(orch)

	dispatcher := host.NewDispatcher(registry)
	dispatcher.SetDefault("orchestrator")

	log.Printf("Registered %d agents, transport=%s", len(registry.List()), *transport)

	switch *transport {
	case "stdio":
		runStdio(registry, dispatcher)
	default:
		runHTTP(cfg, registry, dispatcher)
	}
}

func runHTTP(cfg *config.Config, registry *host.Registry, dispatcher *host.Dispatcher) {
	mux := http.NewServeMux()

	// Handle CORS preflight requests
	mux.HandleFunc("OPTIONS /", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// File-based direct agent endpoint (most specific - register first)
	mux.HandleFunc("POST /agent/{id}/file", func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodySize)
		var req server.FileAgentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		agentReq, err := buildAgentRequestFromFile(req, r.Header.Get("X-GitHub-Token"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), cfg.AgentTimeout)
		defer cancel()

		// Check for ?format=text for plain markdown output
		if r.URL.Query().Get("format") == "text" {
			buf := server.NewBufferEmitter()
			if err := dispatcher.Dispatch(ctx, agentID, agentReq, buf); err != nil {
				buf.SendError(err.Error())
			}
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			w.Write([]byte(buf.String()))
			return
		}

		// Default: SSE streaming
		sse := server.NewSSEWriter(w)
		if sse == nil {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}
		if err := dispatcher.Dispatch(ctx, agentID, agentReq, sse); err != nil {
			sse.SendError(err.Error())
		}
		sse.SendDone()
	})

	// File-based orchestrator endpoint
	mux.HandleFunc("POST /agent/file", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodySize)
		var req server.FileAgentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		agentReq, err := buildAgentRequestFromFile(req, r.Header.Get("X-GitHub-Token"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), cfg.AgentTimeout)
		defer cancel()

		// Check for ?format=text for plain markdown output
		if r.URL.Query().Get("format") == "text" {
			buf := server.NewBufferEmitter()
			if err := dispatcher.Dispatch(ctx, "", agentReq, buf); err != nil {
				buf.SendError(err.Error())
			}
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			w.Write([]byte(buf.String()))
			return
		}

		// Default: SSE streaming
		sse := server.NewSSEWriter(w)
		if sse == nil {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}
		if err := dispatcher.Dispatch(ctx, "", agentReq, sse); err != nil {
			sse.SendError(err.Error())
		}
		sse.SendDone()
	})

	// Specific agent endpoint
	mux.HandleFunc("POST /agent/{id}", func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodySize)

		var req server.AgentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		sse := server.NewSSEWriter(w)
		if sse == nil {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}

		agentReq := protocol.AgentRequest{
			Messages: make([]protocol.Message, len(req.Messages)),
			Token:    r.Header.Get("X-GitHub-Token"),
		}
		for i, m := range req.Messages {
			agentReq.Messages[i] = protocol.Message{Role: m.Role, Content: m.Content}
		}
		host.ParseAndEnrich(&agentReq)

		// Add timeout for agent dispatch
		ctx, cancel := context.WithTimeout(r.Context(), cfg.AgentTimeout)
		defer cancel()

		if err := dispatcher.Dispatch(ctx, agentID, agentReq, sse); err != nil {
			sse.SendError(err.Error())
		}
		sse.SendDone()
	})

	// Agent endpoint — uses orchestrator as default
	mux.HandleFunc("POST /agent", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodySize)
		var req server.AgentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		sse := server.NewSSEWriter(w)
		if sse == nil {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}

		agentReq := protocol.AgentRequest{
			Messages: make([]protocol.Message, len(req.Messages)),
			Token:    r.Header.Get("X-GitHub-Token"),
		}
		for i, m := range req.Messages {
			agentReq.Messages[i] = protocol.Message{Role: m.Role, Content: m.Content}
		}
		host.ParseAndEnrich(&agentReq)

		// Add timeout for agent dispatch
		ctx, cancel := context.WithTimeout(r.Context(), cfg.AgentTimeout)
		defer cancel()

		if err := dispatcher.Dispatch(ctx, "", agentReq, sse); err != nil {
			sse.SendError(err.Error())
		}
		sse.SendDone()
	})

	// Agent listing
	mux.HandleFunc("GET /agents", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(registry.List())
	})

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "ok",
			"service":     "ghcp-iac-agent-host",
			"version":     version,
			"environment": cfg.Environment,
			"agents":      len(registry.List()),
		})
	})

	// Web UI for blast radius analysis
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(blastRadiusHTML))
	})

	port := cfg.Port
	if port == "" {
		port = "8080"
	}

	// Wrap with CORS middleware for browser access
	var handler http.Handler = corsMiddleware(mux)
	// Then wrap with signature verification middleware
	handler = auth.Middleware(cfg.WebhookSecret, cfg.IsDev())(handler)

	// Configure server with timeouts
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	log.Printf("agent-host listening on :%s (version=%s commit=%s)", port, version, commit)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

func buildAgentRequestFromFile(req server.FileAgentRequest, token string) (protocol.AgentRequest, error) {
	if strings.TrimSpace(req.Path) == "" {
		return protocol.AgentRequest{}, fmt.Errorf("path is required")
	}

	contentBytes, err := os.ReadFile(req.Path)
	if err != nil {
		return protocol.AgentRequest{}, fmt.Errorf("failed to read file %q: %w", req.Path, err)
	}

	// Wrap file content in code fence for parsing
	wrappedContent := wrapFileContent(req.Path, string(contentBytes))

	// Combine prompt + content for the message, but keep prompt separate for intent detection
	messageContent := wrappedContent
	if strings.TrimSpace(req.Prompt) != "" {
		messageContent = req.Prompt + "\n\n" + wrappedContent
	}

	agentReq := protocol.AgentRequest{
		Prompt: req.Prompt, // Keep user's intent prompt separate for detection
		Messages: []protocol.Message{
			{Role: "user", Content: messageContent},
		},
		Token: token,
	}
	host.ParseAndEnrich(&agentReq)
	return agentReq, nil
}

func wrapFileContent(path, content string) string {
	lang := "hcl"
	switch strings.ToLower(filepath.Ext(path)) {
	case ".bicep":
		lang = "bicep"
	case ".json", ".tfstate":
		lang = "json"
	}
	return fmt.Sprintf("```%s\n%s\n```", lang, content)
}

func runStdio(registry *host.Registry, dispatcher *host.Dispatcher) {
	log.SetOutput(os.Stderr) // Keep logs on stderr, stdout is for MCP
	log.Println("Starting MCP stdio transport")
	adapter := mcpstdio.NewAdapter(registry, dispatcher, os.Stdin, os.Stdout)
	if err := adapter.Run(context.Background()); err != nil {
		log.Fatalf("MCP stdio error: %v", err)
	}
}

// corsMiddleware adds CORS headers for browser access
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-GitHub-Token")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

const blastRadiusHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blast Radius Analyzer</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            min-height: 100vh;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            color: #58a6ff;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        h1::before { content: "💥"; }
        .form-group { margin-bottom: 1rem; }
        label {
            display: block;
            color: #8b949e;
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
        }
        input, textarea, select {
            width: 100%;
            padding: 0.75rem;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 1rem;
        }
        input:focus, textarea:focus {
            outline: none;
            border-color: #58a6ff;
        }
        textarea { min-height: 200px; font-family: 'Consolas', monospace; }
        .btn-row { display: flex; gap: 1rem; margin: 1.5rem 0; }
        button {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-primary {
            background: #238636;
            color: white;
        }
        .btn-primary:hover { background: #2ea043; }
        .btn-primary:disabled {
            background: #21262d;
            color: #484f58;
            cursor: not-allowed;
        }
        .btn-secondary {
            background: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
        }
        .btn-secondary:hover { background: #30363d; }
        .output-section {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 1.5rem;
            margin-top: 1rem;
        }
        .output-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #30363d;
        }
        .output-header h2 { color: #58a6ff; font-size: 1.2rem; }
        #output {
            white-space: pre-wrap;
            font-family: 'Consolas', monospace;
            line-height: 1.6;
        }
        #output h2, #output h3, #output h4 { color: #58a6ff; margin: 1rem 0 0.5rem; }
        #output strong { color: #f0883e; }
        #output code {
            background: #21262d;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            color: #79c0ff;
        }
        .status {
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-size: 0.85rem;
        }
        .status.loading { background: #1f6feb33; color: #58a6ff; }
        .status.success { background: #23863633; color: #3fb950; }
        .status.error { background: #f8514933; color: #f85149; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
        @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
        .examples {
            background: #21262d;
            padding: 1rem;
            border-radius: 6px;
            margin-top: 1rem;
        }
        .examples h3 { color: #8b949e; font-size: 0.9rem; margin-bottom: 0.5rem; }
        .example-btn {
            background: transparent;
            border: 1px solid #30363d;
            color: #58a6ff;
            padding: 0.4rem 0.8rem;
            font-size: 0.85rem;
            margin: 0.25rem;
        }
        .example-btn:hover { background: #30363d; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Blast Radius Analyzer</h1>
        
        <div class="form-group">
            <label>File Path (local path to .tf or .tfstate)</label>
            <input type="text" id="filePath" placeholder="C:\path\to\main.tf">
        </div>

        <div class="form-group">
            <label>Prompt (describe what you want to change/analyze)</label>
            <input type="text" id="prompt" placeholder="e.g., delete azurerm_firewall.hub">
        </div>

        <div class="examples">
            <h3>Example prompts:</h3>
            <button class="example-btn" onclick="setPrompt('delete the firewall')">delete the firewall</button>
            <button class="example-btn" onclick="setPrompt('change hub_to_spoke_prod peering')">change peering</button>
            <button class="example-btn" onclick="setPrompt('modify prod_server VM')">modify prod VM</button>
            <button class="example-btn" onclick="setPrompt('routing change in spoke_prod')">routing change</button>
            <button class="example-btn" onclick="setPrompt('')">full analysis</button>
        </div>

        <div class="btn-row">
            <button class="btn-primary" id="analyzeBtn" onclick="analyze()">🔍 Analyze Blast Radius</button>
            <button class="btn-secondary" onclick="clearOutput()">Clear</button>
        </div>

        <div class="output-section">
            <div class="output-header">
                <h2>Analysis Result</h2>
                <span id="status" class="status" style="display: none;"></span>
            </div>
            <div id="output">Click "Analyze" to see the blast radius analysis...</div>
        </div>
    </div>

    <script>
        function setPrompt(text) {
            document.getElementById('prompt').value = text;
        }

        function showStatus(message, type) {
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = 'status ' + type;
            status.style.display = 'inline-block';
        }

        function clearOutput() {
            document.getElementById('output').innerHTML = 'Click "Analyze" to see the blast radius analysis...';
            document.getElementById('status').style.display = 'none';
        }

        async function analyze() {
            const filePath = document.getElementById('filePath').value.trim();
            const prompt = document.getElementById('prompt').value.trim();
            const btn = document.getElementById('analyzeBtn');
            const output = document.getElementById('output');

            if (!filePath) {
                alert('Please enter a file path');
                return;
            }

            btn.disabled = true;
            btn.textContent = '⏳ Analyzing...';
            showStatus('Loading...', 'loading');
            output.innerHTML = '';

            try {
                const response = await fetch('/agent/impact/file?format=text', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: filePath, prompt: prompt })
                });

                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ': ' + (await response.text()));
                }

                const text = await response.text();
                output.innerHTML = formatMarkdown(text);
                showStatus('Complete', 'success');
            } catch (err) {
                output.innerHTML = '<span style="color: #f85149;">Error: ' + err.message + '</span>';
                showStatus('Error', 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = '🔍 Analyze Blast Radius';
            }
        }

        function formatMarkdown(text) {
            var backtick = String.fromCharCode(96);
            return text
                .replace(/^## (.+)$/gm, '<h2>$1</h2>')
                .replace(/^### (.+)$/gm, '<h3>$1</h3>')
                .replace(/^#### (.+)$/gm, '<h4>$1</h4>')
                .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
                .replace(new RegExp(backtick + '([^' + backtick + ']+)' + backtick, 'g'), '<code>$1</code>')
                .replace(/^- (.+)$/gm, '• $1')
                .replace(/\n/g, '<br>');
        }
    </script>
</body>
</html>`
