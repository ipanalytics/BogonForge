package bogonforge

import "testing"

func TestParseIPCSVDocumentationPolicy(t *testing.T) {
	data := `Address Block,Name,RFC,Allocation Date,Termination Date,Source,Destination,Forwardable,Globally Reachable,Reserved-by-Protocol
192.0.2.0/24,Documentation (TEST-NET-1),[RFC5737],2010-01,N/A,False,False,False,False,False
100.64.0.0/10,Shared Address Space,[RFC6598],2012-04,N/A,True,True,True,False,False
`
	records, err := parseIPCSV(data, "ipv4", "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records", len(records))
	}
	doc := records[0]
	if doc.Class != "documentation" {
		t.Fatalf("class = %q", doc.Class)
	}
	for _, want := range []string{"exclude_from_geoip", "exclude_from_reputation", "exclude_from_provider_map", "allow_in_examples"} {
		if !contains(doc.DatasetPolicy, want) {
			t.Fatalf("missing policy %q in %#v", want, doc.DatasetPolicy)
		}
	}
	shared := records[1]
	if shared.Class != "shared-address-space" {
		t.Fatalf("class = %q", shared.Class)
	}
	if !contains(shared.DatasetPolicy, "exclude_from_geoip") {
		t.Fatalf("shared space should be geo excluded")
	}
}

func TestParseASNCSV(t *testing.T) {
	data := `AS Number,Reason for Reservation,Reference
64496-64511,For documentation and sample code; reserved by [RFC5398],[RFC5398]
64512-65534,For private use; reserved by [RFC6996],[RFC6996]
`
	records, err := parseASNCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	if records[0].Class != "documentation" || !contains(records[0].DatasetPolicy, "allow_in_examples") {
		t.Fatalf("unexpected documentation asn record: %#v", records[0])
	}
	if records[1].Class != "private-use" || !contains(records[1].DatasetPolicy, "exclude_from_public_asn_identity") {
		t.Fatalf("unexpected private asn record: %#v", records[1])
	}
}

func TestInspectLongestPrefix(t *testing.T) {
	falseValue := false
	trueValue := true
	records := []IPRecord{
		{Prefix: "192.0.0.0/24", Facts: IPFacts{GloballyReachable: &falseValue}},
		{Prefix: "192.0.0.9/32", Facts: IPFacts{GloballyReachable: &trueValue}},
	}
	rec, ok, err := Inspect(records, "192.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || rec.Prefix != "192.0.0.9/32" {
		t.Fatalf("got %#v ok=%v", rec, ok)
	}
}
