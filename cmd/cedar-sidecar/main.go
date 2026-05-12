package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	cedar "github.com/cedar-policy/cedar-go"
)

type AuthorizeRequest struct {
	Principal string          `json:"principal"`
	Action    string          `json:"action"`
	Resource  string          `json:"resource"`
	Entities  cedar.EntityMap `json:"entities"`
	Context   map[string]any  `json:"context"`
}

type AuthorizeResponse struct {
	Decision string   `json:"decision"`
	Reasons  []string `json:"reasons"`
}

var policySet *cedar.PolicySet

func main() {
	ps, err := loadPolicies(envOr("CEDAR_POLICY_DIR", "/policies"))
	if err != nil {
		log.Fatalf("failed to load policies: %v", err)
	}
	policySet = ps

	http.HandleFunc("/authorize", handleAuthorize)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	addr := envOr("LISTEN_ADDR", ":8080")
	log.Printf("cedar-sidecar listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuthorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	var principal cedar.EntityUID
	if err := principal.UnmarshalCedar([]byte(req.Principal)); err != nil {
		if err2 := json.Unmarshal([]byte(req.Principal), &principal); err2 != nil {
			http.Error(w, "invalid principal: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	var action cedar.EntityUID
	if err := action.UnmarshalCedar([]byte(req.Action)); err != nil {
		if err2 := json.Unmarshal([]byte(req.Action), &action); err2 != nil {
			http.Error(w, "invalid action: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	var resource cedar.EntityUID
	if err := resource.UnmarshalCedar([]byte(req.Resource)); err != nil {
		if err2 := json.Unmarshal([]byte(req.Resource), &resource); err2 != nil {
			http.Error(w, "invalid resource: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	ctx := cedar.NewRecord(toRecordMap(req.Context))

	decision, diag := policySet.IsAuthorized(req.Entities, cedar.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   ctx,
	})

	resp := AuthorizeResponse{Decision: "DENY"}
	if decision == cedar.Allow {
		resp.Decision = "ALLOW"
	}
	for _, reason := range diag.Reasons {
		policy := policySet.Get(reason.PolicyID)
		if policy == nil {
			continue
		}
		anns := policy.Annotations()
		if msg, ok := anns["reason"]; ok {
			resp.Reasons = append(resp.Reasons, string(msg))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func loadPolicies(dir string) (*cedar.PolicySet, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	combined := cedar.NewPolicySet()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(dir + "/" + entry.Name())
		if err != nil {
			return nil, err
		}
		ps, err := cedar.NewPolicySetFromBytes(entry.Name(), data)
		if err != nil {
			return nil, err
		}
		for id, p := range ps.All() {
			combined.Add(id, p)
		}
	}
	return combined, nil
}

func toRecordMap(m map[string]any) cedar.RecordMap {
	rm := make(cedar.RecordMap, len(m))
	for k, v := range m {
		rm[cedar.String(k)] = anyCedarValue(v)
	}
	return rm
}

func anyCedarValue(v any) cedar.Value {
	switch val := v.(type) {
	case bool:
		return cedar.Boolean(val)
	case float64:
		return cedar.Long(int64(val))
	case string:
		return cedar.String(val)
	case []any:
		elems := make([]cedar.Value, len(val))
		for i, elem := range val {
			elems[i] = anyCedarValue(elem)
		}
		return cedar.NewSet(elems...)
	default:
		return cedar.String("")
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
