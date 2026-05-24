package main

import (
	"bytes"
	"encoding/json"
	"sync"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

type policyInfo struct {
	File  string `json:"file"`
	Count int    `json:"count"`
}

var policyMeta []policyInfo

type evalEntry struct {
	TS        time.Time `json:"ts"`
	Principal string    `json:"principal"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Decision  string    `json:"decision"`
	Reasons   []string  `json:"reasons,omitempty"`
}

type evalRing struct {
	mu      sync.Mutex
	entries []evalEntry
	max     int
}

func newEvalRing(max int) *evalRing {
	return &evalRing{entries: make([]evalEntry, 0, max), max: max}
}

func (r *evalRing) add(e evalEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, e)
	if len(r.entries) > r.max {
		r.entries = r.entries[len(r.entries)-r.max:]
	}
}

func (r *evalRing) snapshot() []evalEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]evalEntry, len(r.entries))
	for i, e := range r.entries {
		out[len(r.entries)-1-i] = e
	}
	return out
}

var evalLog = newEvalRing(200)

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
	http.HandleFunc("/", handleUI)
	http.HandleFunc("/ui", handleUI)
	http.HandleFunc("/api/evaluations", handleAPIEvaluations)
	http.HandleFunc("/api/policies", handleAPIPolicies)

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
		if msg, ok := policy.Annotations()["reason"]; ok {
			resp.Reasons = append(resp.Reasons, string(msg))
		}
	}
	if decision == cedar.Deny {
		fireAlert(req.Principal, req.Action, req.Resource, resp.Reasons)
	}

	evalLog.add(evalEntry{
		TS:        time.Now().UTC(),
		Principal: req.Principal,
		Action:    req.Action,
		Resource:  req.Resource,
		Decision:  resp.Decision,
		Reasons:   resp.Reasons,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleAPIEvaluations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(evalLog.snapshot())
}

func handleAPIPolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	total := 0
	for range policySet.All() {
		total++
	}
	type polResp struct {
		Files []policyInfo `json:"files"`
		Total int          `json:"total"`
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(polResp{Files: policyMeta, Total: total})
}

func handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/ui" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(cedarSpaHTML))
}

func loadPolicies(dir string) (*cedar.PolicySet, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	policyMeta = nil
	combined := cedar.NewPolicySet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cedar") {
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
		prefix := strings.TrimSuffix(entry.Name(), ".cedar")
		count := 0
		for id, p := range ps.All() {
			combined.Add(cedar.PolicyID(prefix+"/"+string(id)), p)
			count++
		}
		policyMeta = append(policyMeta, policyInfo{File: entry.Name(), Count: count})
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

var alertmanagerURL = envOr("ALERTMANAGER_URL", "")

func fireAlert(principal, action, resource string, reasons []string) {
	if alertmanagerURL == "" {
		return
	}
	msg := strings.Join(reasons, "; ")
	if msg == "" {
		msg = "policy denied"
	}
	now := time.Now().UTC()
	payload, _ := json.Marshal([]map[string]any{{
		"labels": map[string]string{
			"alertname": "CedarPolicyDeny",
			"action":    action,
			"severity":  "warning",
		},
		"annotations": map[string]string{
			"summary": fmt.Sprintf("Cedar denied %s for %s on %s", action, principal, resource),
			"reason":  msg,
		},
		"startsAt": now.Format(time.RFC3339),
		"endsAt":   now.Add(5 * time.Minute).Format(time.RFC3339),
	}})
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(alertmanagerURL+"/api/v1/alerts", "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("alertmanager post failed: %v", err)
		return
	}
	resp.Body.Close()
}

const cedarSpaHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Cedar Service</title>
<style>
:root {
  --bg:     #0d1117;
  --bg2:    #161b22;
  --bg3:    #21262d;
  --border: #30363d;
  --text:   #c9d1d9;
  --muted:  #8b949e;
  --green:  #3fb950;
  --red:    #f85149;
  --yellow: #d29922;
  --blue:   #58a6ff;
  --font:   'SF Mono','Fira Code','Cascadia Code',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;line-height:1.5}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:10px 24px;display:flex;align-items:center;gap:16px}
header h1{font-size:13px;color:var(--blue);font-weight:normal}
main{padding:20px 24px;max-width:1400px}
.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:left;color:var(--muted);padding:6px 10px;border-bottom:1px solid var(--border);font-weight:normal;font-size:11px;text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}
.tbl td{padding:6px 10px;border-bottom:1px solid var(--border);overflow:hidden;text-overflow:ellipsis;max-width:400px}
.badge{display:inline-block;padding:1px 5px;border-radius:3px;font-size:11px}
.br{background:rgba(248,81,73,.15);color:var(--red)}
.bg{background:rgba(63,185,80,.15);color:var(--green)}
.bm{background:var(--bg3);color:var(--muted)}
.stats{display:flex;gap:28px;padding:14px 16px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:20px}
.stat-label{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px}
.stat-val{font-size:22px;margin-top:2px}
.stat-val.red{color:var(--red)}
.stat-val.green{color:var(--green)}
.sec{margin-bottom:24px}
.sec-title{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding-bottom:8px;border-bottom:1px solid var(--border);margin-bottom:10px}
.dim{color:var(--muted)}
.msg{color:var(--muted);padding:20px 0;text-align:center;font-size:12px}
.err{color:var(--red);padding:20px 0;font-size:12px}
</style>
</head>
<body>
<header>
  <h1>platform-cedar-sidecar</h1>
</header>
<main id="app"><div class="msg">loading&#8230;</div></main>
<script>
'use strict';
async function loadAll(){
  var app=document.getElementById('app');
  try{
    var results=await Promise.all([fetch('/api/policies').then(function(r){return r.json();}),fetch('/api/evaluations').then(function(r){return r.json();})]);
    var polData=results[0],evalData=results[1];
    var allow=0,deny=0;
    for(var i=0;i<evalData.length;i++){if(evalData[i].decision==='ALLOW')allow++;else deny++;}
    var h='';
    h+='<div class="stats">'
      +'<div><div class="stat-label">policies</div><div class="stat-val">'+polData.total+'</div></div>'
      +'<div><div class="stat-label">evaluations</div><div class="stat-val">'+evalData.length+'</div></div>'
      +'<div><div class="stat-label">allow</div><div class="stat-val green">'+allow+'</div></div>'
      +'<div><div class="stat-label">deny</div><div class="stat-val'+(deny>0?' red':'')+'">'+deny+'</div></div>'
      +'</div>';
    h+='<div class="sec"><div class="sec-title">policy files ('+polData.files.length+')</div>';
    if(!polData.files||!polData.files.length){h+='<div class="msg" style="text-align:left">no policies loaded</div>';}
    else{h+='<table class="tbl"><thead><tr><th>file</th><th>rules</th></tr></thead><tbody>';for(var i=0;i<polData.files.length;i++){var f=polData.files[i];h+='<tr><td>'+esc(f.file)+'</td><td class="dim">'+f.count+'</td></tr>';}h+='</tbody></table>';}
    h+='</div>';
    h+='<div class="sec"><div class="sec-title">recent evaluations ('+evalData.length+')</div>';
    if(!evalData||!evalData.length){h+='<div class="msg" style="text-align:left">no evaluations yet</div>';}
    else{h+='<table class="tbl"><thead><tr><th>decision</th><th>action</th><th>principal</th><th>resource</th><th>reasons</th><th>time</th></tr></thead><tbody>';for(var i=0;i<evalData.length;i++){var e=evalData[i];var db=e.decision==='ALLOW'?'<span class="badge bg">ALLOW</span>':'<span class="badge br">DENY</span>';var reasons=e.reasons&&e.reasons.length?'<span style="color:var(--red)">'+esc(e.reasons.join('; '))+'</span>':'<span class="dim">—</span>';var action=e.action.replace(/.*::/,'').replace(/"/g,'');h+='<tr><td>'+db+'</td><td>'+esc(action)+'</td><td class="dim" title="'+esc(e.principal)+'">'+esc(trimUID(e.principal))+'</td><td class="dim" title="'+esc(e.resource)+'">'+esc(trimUID(e.resource))+'</td><td>'+reasons+'</td><td class="dim">'+fmtTime(e.ts)+'</td></tr>';}h+='</tbody></table>';}
    h+='</div>';
    app.innerHTML=h;
  }catch(e2){app.innerHTML='<div class="err">failed to load: '+esc(e2.message)+'</div>';}
}
function trimUID(s){var m=s.match(/"([^"]+)"/);return m?m[1]:s;}
function fmtTime(ts){if(!ts)return'—';return new Date(ts).toISOString().replace('T',' ').replace('Z','').split('.')[0];}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
loadAll();
setInterval(loadAll,15000);
</script>
</body>
</html>`
