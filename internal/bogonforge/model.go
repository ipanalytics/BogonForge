package bogonforge

type BoolValue *bool

type IPRecord struct {
	Prefix        string   `json:"prefix"`
	Family        string   `json:"family"`
	Class         string   `json:"class"`
	Name          string   `json:"name"`
	Facts         IPFacts  `json:"facts"`
	DatasetPolicy []string `json:"dataset_policy"`
}

type IPFacts struct {
	Source             string    `json:"source"`
	RFC                []string  `json:"rfc"`
	GloballyReachable  BoolValue `json:"globally_reachable"`
	Forwardable        BoolValue `json:"forwardable"`
	SourceValid        BoolValue `json:"source_valid"`
	DestinationValid   BoolValue `json:"destination_valid"`
	ReservedByProtocol BoolValue `json:"reserved_by_protocol"`
	Stability          string    `json:"stability"`
	AllocationDate     string    `json:"allocation_date,omitempty"`
	TerminationDate    string    `json:"termination_date,omitempty"`
}

type ASNRecord struct {
	ASNRange      string   `json:"asn_range"`
	Class         string   `json:"class"`
	Reason        string   `json:"reason"`
	Facts         ASNFacts `json:"facts"`
	DatasetPolicy []string `json:"dataset_policy"`
}

type ASNFacts struct {
	Source    string   `json:"source"`
	RFC       []string `json:"rfc"`
	Stability string   `json:"stability"`
}

type Metadata struct {
	BuildID     string            `json:"build_id"`
	Sources     map[string]string `json:"sources"`
	IPRecords   int               `json:"ip_records"`
	ASNRecords  int               `json:"asn_records"`
	GeneratedAt string            `json:"generated_at"`
}

type ImpactDiff struct {
	BuildID                      string              `json:"build_id"`
	SemanticChanges              int                 `json:"semantic_changes"`
	ProfileImpacts               map[string][]string `json:"profile_impacts"`
	DownstreamRebuildRecommended []string            `json:"downstream_rebuild_recommended"`
}
