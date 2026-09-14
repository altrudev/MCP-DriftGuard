package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

const protocol = "2026-07-28"

func main() {
	mux:=http.NewServeMux()
	mux.HandleFunc("/mcp",mcp)
	log.Println("MCP DriftGuard demo server: http://127.0.0.1:8787/mcp")
	if os.Getenv("MCPDRIFT_DEMO_DRIFT")=="1" {
		log.Println("DRIFT ENABLED: export_customer_database is exposed")
	}
	log.Fatal(http.ListenAndServe("127.0.0.1:8787",mux))
}

func mcp(w http.ResponseWriter,r *http.Request) {
	if r.Method!=http.MethodPost {
		http.Error(w,"POST required",http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		JSONRPC string `json:"jsonrpc"`
		ID any `json:"id"`
		Method string `json:"method"`
		Params map[string]any `json:"params"`
	}
	if err:=json.NewDecoder(r.Body).Decode(&req);err!=nil {
		http.Error(w,err.Error(),http.StatusBadRequest)
		return
	}
	if r.Header.Get("MCP-Protocol-Version")!=protocol || r.Header.Get("Mcp-Method")!=req.Method {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc":"2.0",
			"id":req.ID,
			"error":map[string]any{"code":-32020,"message":"header mismatch"},
		})
		return
	}
	w.Header().Set("Content-Type","application/json")
	switch req.Method {
	case "server/discover":
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc":"2.0",
			"id":req.ID,
			"result":map[string]any{
				"resultType":"complete",
				"supportedVersions":[]string{protocol},
				"capabilities":map[string]any{"tools":map[string]any{}},
				"_meta":map[string]any{
					"io.modelcontextprotocol/serverInfo":map[string]any{
						"name":"mcpdrift-demo",
						"version":"1.0.0",
					},
				},
			},
		})
	case "tools/list":
		tools:=[]any{
			map[string]any{
				"name":"customer_search",
				"description":"Search customer records",
				"inputSchema":map[string]any{
					"type":"object",
					"additionalProperties":false,
					"properties":map[string]any{
						"query":map[string]any{"type":"string"},
					},
					"required":[]string{"query"},
				},
			},
		}
		if os.Getenv("MCPDRIFT_DEMO_DRIFT")=="1" {
			tools=append(tools,map[string]any{
				"name":"export_customer_database",
				"description":"Export the customer database",
				"inputSchema":map[string]any{
					"type":"object",
					"additionalProperties":false,
					"properties":map[string]any{},
				},
			})
		}
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc":"2.0",
			"id":req.ID,
			"result":map[string]any{
				"resultType":"complete",
				"tools":tools,
			},
		})
	default:
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc":"2.0",
			"id":req.ID,
			"error":map[string]any{"code":-32601,"message":"Method not found"},
		})
	}
}
