package bogonforge

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const (
	DefaultIPv4URL = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv"
	DefaultIPv6URL = "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv"
	DefaultASNURL  = "https://www.iana.org/assignments/iana-as-numbers-special-registry/special-purpose-as-numbers.csv"
)

var rfcRE = regexp.MustCompile(`RFC(?: Errata )?[0-9]+`)

func FetchIPRecords(ipv4URL, ipv6URL string) ([]IPRecord, error) {
	var out []IPRecord
	v4, err := fetchCSV(ipv4URL)
	if err != nil {
		return nil, fmt.Errorf("fetch ipv4 registry: %w", err)
	}
	v4records, err := parseIPCSV(v4, "ipv4", "iana-ipv4-special-registry")
	if err != nil {
		return nil, err
	}
	out = append(out, v4records...)

	v6, err := fetchCSV(ipv6URL)
	if err != nil {
		return nil, fmt.Errorf("fetch ipv6 registry: %w", err)
	}
	v6records, err := parseIPCSV(v6, "ipv6", "iana-ipv6-special-registry")
	if err != nil {
		return nil, err
	}
	out = append(out, v6records...)
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out, nil
}

func FetchASNRecords(asnURL string) ([]ASNRecord, error) {
	body, err := fetchCSV(asnURL)
	if err != nil {
		return nil, fmt.Errorf("fetch asn registry: %w", err)
	}
	return parseASNCSV(body)
}

func fetchCSV(url string) (string, error) {
	res, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return "", fmt.Errorf("http %d from %s", res.StatusCode, url)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseIPCSV(data, family, source string) ([]IPRecord, error) {
	r := csv.NewReader(strings.NewReader(data))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse %s csv: %w", family, err)
	}
	var out []IPRecord
	for i, row := range rows {
		if i == 0 {
			continue
		}
		if len(row) < 10 {
			return nil, fmt.Errorf("%s row %d has %d fields", family, i+1, len(row))
		}
		stability := "permanent"
		if clean(row[4]) != "" && clean(row[4]) != "N/A" {
			stability = "terminated"
		}
		prefixes := splitPrefixes(row[0])
		for _, prefix := range prefixes {
			name := clean(row[1])
			rec := IPRecord{
				Prefix: prefix,
				Family: family,
				Class:  classifyIP(name, prefix),
				Name:   name,
				Facts: IPFacts{
					Source:             source,
					RFC:                extractRFCs(row[2]),
					AllocationDate:     clean(row[3]),
					TerminationDate:    clean(row[4]),
					SourceValid:        parseIanaBool(row[5]),
					DestinationValid:   parseIanaBool(row[6]),
					Forwardable:        parseIanaBool(row[7]),
					GloballyReachable:  parseIanaBool(row[8]),
					ReservedByProtocol: parseIanaBool(row[9]),
					Stability:          stability,
				},
			}
			rec.DatasetPolicy = DataPolicy(rec)
			out = append(out, rec)
		}
	}
	return out, nil
}

func parseASNCSV(data string) ([]ASNRecord, error) {
	r := csv.NewReader(strings.NewReader(data))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse asn csv: %w", err)
	}
	var out []ASNRecord
	for i, row := range rows {
		if i == 0 {
			continue
		}
		if len(row) < 3 {
			return nil, fmt.Errorf("asn row %d has %d fields", i+1, len(row))
		}
		rec := ASNRecord{
			ASNRange: clean(row[0]),
			Class:    classifyASN(row[1]),
			Reason:   clean(row[1]),
			Facts: ASNFacts{
				Source:    "iana-as-numbers-special-registry",
				RFC:       extractRFCs(row[2]),
				Stability: "permanent",
			},
		}
		rec.DatasetPolicy = ASNPolicy(rec)
		out = append(out, rec)
	}
	return out, nil
}

func splitPrefixes(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = clean(strings.Split(part, " ")[0])
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func clean(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	s = strings.Trim(s, `"`)
	return strings.TrimSpace(s)
}

func parseIanaBool(s string) BoolValue {
	s = strings.ToLower(clean(s))
	if strings.HasPrefix(s, "true") {
		v := true
		return &v
	}
	if strings.HasPrefix(s, "false") {
		v := false
		return &v
	}
	return nil
}

func extractRFCs(s string) []string {
	matches := rfcRE.FindAllString(s, -1)
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		m = strings.ReplaceAll(m, "RFC Errata ", "RFC-ERRATA-")
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}
