package scanner

import "encoding/json"

// Result holds the aggregate scan output.
type Result struct {
	Host       json.RawMessage            `json:"host,omitempty"`
	Network    json.RawMessage            `json:"network,omitempty"`
	Storage    json.RawMessage            `json:"storage,omitempty"`
	Containers json.RawMessage            `json:"containers,omitempty"`
	Cluster    json.RawMessage            `json:"cluster,omitempty"`
	Power      json.RawMessage            `json:"power,omitempty"`
	IoT        json.RawMessage            `json:"iot,omitempty"`
	GPU        json.RawMessage            `json:"gpu,omitempty"`
	Services   json.RawMessage            `json:"services,omitempty"`
	Phases     map[string]json.RawMessage `json:"-"`
	Meta       ResultMeta                 `json:"meta"`
}

// ResultMeta holds scan metadata.
type ResultMeta struct {
	Version      string   `json:"version"`
	DurationMS   int      `json:"duration_ms"`
	Profile      string   `json:"profile"`
	Phases       []string `json:"phases"`
	SourceHost   string   `json:"source_host"`
	InferredRole string   `json:"inferred_role,omitempty"`
}

// NewResult creates an empty Result.
func NewResult() *Result {
	return &Result{
		Phases: make(map[string]json.RawMessage),
	}
}

// Set stores scanner output by name and maps it to the top-level field.
func (r *Result) Set(name string, data json.RawMessage) {
	r.Phases[name] = data
	r.Meta.Phases = append(r.Meta.Phases, name)

	switch name {
	case "host":
		r.Host = data
	case "network":
		r.Network = data
	case "storage":
		r.Storage = data
	case "containers":
		r.Containers = data
	case "cluster":
		r.Cluster = data
	case "power":
		r.Power = data
	case "iot":
		r.IoT = data
	case "gpu":
		r.GPU = data
	case "services":
		r.Services = data
	}
}
