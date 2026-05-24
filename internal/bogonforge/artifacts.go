package bogonforge

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type BuildOptions struct {
	Out     string
	IPv4URL string
	IPv6URL string
	ASNURL  string
	Now     time.Time
}

func Build(opts BuildOptions) error {
	if opts.IPv4URL == "" {
		opts.IPv4URL = DefaultIPv4URL
	}
	if opts.IPv6URL == "" {
		opts.IPv6URL = DefaultIPv6URL
	}
	if opts.ASNURL == "" {
		opts.ASNURL = DefaultASNURL
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.Out == "" {
		opts.Out = "release/current"
	}

	ipRecords, err := FetchIPRecords(opts.IPv4URL, opts.IPv6URL)
	if err != nil {
		return err
	}
	asnRecords, err := FetchASNRecords(opts.ASNURL)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(opts.Out, "profiles"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(opts.Out, "configs"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(opts.Out, "schemas"), 0o755); err != nil {
		return err
	}

	if err := writeJSONLGZ(filepath.Join(opts.Out, "bogonforge.jsonl.gz"), ipRecords); err != nil {
		return err
	}
	if err := writeIPCSV(filepath.Join(opts.Out, "bogonforge.csv.gz"), ipRecords); err != nil {
		return err
	}
	if err := writeJSONLGZ(filepath.Join(opts.Out, "bogonforge-asn.jsonl.gz"), asnRecords); err != nil {
		return err
	}
	if err := writeASNCSV(filepath.Join(opts.Out, "bogonforge-asn.csv.gz"), asnRecords); err != nil {
		return err
	}

	dataProfile := profileRecords("data-policy", ipRecords)
	if err := writePrettyJSON(filepath.Join(opts.Out, "profiles", "data-policy.json"), dataProfile); err != nil {
		return err
	}
	edgeDrop := EdgeDrop(ipRecords)
	labAllow := LabAllow(ipRecords)
	geoExclude := GeoIPExclude(ipRecords)
	if err := writeLines(filepath.Join(opts.Out, "profiles", "edge-drop.txt"), edgeDrop); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(opts.Out, "profiles", "lab-allow.txt"), labAllow); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(opts.Out, "profiles", "geoip-exclude.txt"), geoExclude); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(opts.Out, "configs", "nftables-set.nft"), nftables(edgeDrop)); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(opts.Out, "configs", "ipset.restore"), ipset(edgeDrop)); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(opts.Out, "configs", "nginx-deny.conf"), nginx(edgeDrop)); err != nil {
		return err
	}
	for _, schema := range []string{"special-ip.schema.json", "special-asn.schema.json", "policy-profile.schema.json"} {
		b, err := os.ReadFile(filepath.Join("schemas", schema))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(opts.Out, "schemas", schema), b, 0o644); err != nil {
			return err
		}
	}

	buildID := opts.Now.Format("20060102-150405Z")
	meta := Metadata{
		BuildID: buildID,
		Sources: map[string]string{
			"ipv4": opts.IPv4URL,
			"ipv6": opts.IPv6URL,
			"asn":  opts.ASNURL,
		},
		IPRecords:   len(ipRecords),
		ASNRecords:  len(asnRecords),
		GeneratedAt: opts.Now.Format(time.RFC3339),
	}
	if err := writePrettyJSON(filepath.Join(opts.Out, "metadata.json"), meta); err != nil {
		return err
	}
	impact := ImpactDiff{
		BuildID:         buildID,
		SemanticChanges: len(ipRecords) + len(asnRecords),
		ProfileImpacts: map[string][]string{
			"data-policy": GeoIPExclude(ipRecords),
			"edge-drop":   edgeDrop,
			"lab-allow":   labAllow,
		},
		DownstreamRebuildRecommended: []string{"GeoForge", "Blackroute", "ASNForge", "PrefixLint", "IntelMerge"},
	}
	if err := writePrettyJSON(filepath.Join(opts.Out, "impact-diff.json"), impact); err != nil {
		return err
	}
	if err := writeQualityReport(opts.Out, ipRecords, asnRecords); err != nil {
		return err
	}
	return writeChecksums(opts.Out)
}

func LoadIPRecords(db string) ([]IPRecord, error) {
	f, err := os.Open(db)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	dec := json.NewDecoder(gz)
	var out []IPRecord
	for dec.More() {
		var r IPRecord
		if err := dec.Decode(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func Inspect(records []IPRecord, ip string) (IPRecord, bool, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return IPRecord{}, false, err
	}
	var best IPRecord
	bestBits := -1
	for _, r := range records {
		prefix, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			continue
		}
		if prefix.Contains(addr) && prefix.Bits() > bestBits {
			best = r
			bestBits = prefix.Bits()
		}
	}
	return best, bestBits >= 0, nil
}

func Validate(dir string, strict bool) error {
	required := []string{
		"bogonforge.jsonl.gz",
		"bogonforge.csv.gz",
		"bogonforge-asn.jsonl.gz",
		"bogonforge-asn.csv.gz",
		"profiles/data-policy.json",
		"profiles/edge-drop.txt",
		"profiles/lab-allow.txt",
		"profiles/geoip-exclude.txt",
		"configs/nftables-set.nft",
		"configs/ipset.restore",
		"configs/nginx-deny.conf",
		"schemas/special-ip.schema.json",
		"schemas/special-asn.schema.json",
		"schemas/policy-profile.schema.json",
		"metadata.json",
		"impact-diff.json",
		"quality-report.md",
		"checksums.txt",
	}
	if strict {
		// Strict mode validates the currently emitted v0.1 artifacts.
		// MMDB is a tracked release target, but this implementation does not emit it yet.
		// Add bogonforge.mmdb here only after Build() writes it.
	}
	for _, name := range required {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("missing %s", name)
		}
	}
	records, err := LoadIPRecords(filepath.Join(dir, "bogonforge.jsonl.gz"))
	if err != nil {
		return err
	}
	for _, r := range records {
		if _, err := netip.ParsePrefix(r.Prefix); err != nil {
			return fmt.Errorf("invalid prefix %s: %w", r.Prefix, err)
		}
		if r.Facts.Source == "" || len(r.Facts.RFC) == 0 || r.Class == "" {
			return fmt.Errorf("incomplete record %s", r.Prefix)
		}
	}
	return nil
}

func writeJSONLGZ[T any](path string, records []T) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	enc := json.NewEncoder(gz)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

func writeIPCSV(path string, records []IPRecord) error {
	return writeGzipCSV(path, func(w *csv.Writer) error {
		_ = w.Write([]string{"prefix", "family", "class", "name", "rfc", "source", "source_valid", "destination_valid", "forwardable", "globally_reachable", "reserved_by_protocol", "dataset_policy"})
		for _, r := range records {
			_ = w.Write([]string{r.Prefix, r.Family, r.Class, r.Name, strings.Join(r.Facts.RFC, ";"), r.Facts.Source, boolString(r.Facts.SourceValid), boolString(r.Facts.DestinationValid), boolString(r.Facts.Forwardable), boolString(r.Facts.GloballyReachable), boolString(r.Facts.ReservedByProtocol), strings.Join(r.DatasetPolicy, ";")})
		}
		return w.Error()
	})
}

func writeASNCSV(path string, records []ASNRecord) error {
	return writeGzipCSV(path, func(w *csv.Writer) error {
		_ = w.Write([]string{"asn_range", "class", "reason", "rfc", "source", "dataset_policy"})
		for _, r := range records {
			_ = w.Write([]string{r.ASNRange, r.Class, r.Reason, strings.Join(r.Facts.RFC, ";"), r.Facts.Source, strings.Join(r.DatasetPolicy, ";")})
		}
		return w.Error()
	})
}

func writeGzipCSV(path string, fn func(*csv.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	w := csv.NewWriter(gz)
	defer w.Flush()
	return fn(w)
}

func profileRecords(profile string, records []IPRecord) map[string]any {
	var items []map[string]any
	for _, r := range records {
		if len(r.DatasetPolicy) == 0 {
			continue
		}
		items = append(items, map[string]any{"subject": r.Prefix, "policy": r.DatasetPolicy})
	}
	return map[string]any{"profile": profile, "records": items}
}

func writePrettyJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func writeLines(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func nftables(prefixes []string) []string {
	lines := []string{"table inet bogonforge {", "  set edge_drop {", "    type inet_addr", "    flags interval", "    elements = {"}
	for i, p := range prefixes {
		sep := ","
		if i == len(prefixes)-1 {
			sep = ""
		}
		lines = append(lines, "      "+p+sep)
	}
	lines = append(lines, "    }", "  }", "}")
	return lines
}

func ipset(prefixes []string) []string {
	lines := []string{"create bogonforge_edge_drop hash:net family inet hashsize 1024 maxelem 65536"}
	for _, p := range prefixes {
		if strings.Contains(p, ":") {
			continue
		}
		lines = append(lines, "add bogonforge_edge_drop "+p)
	}
	return lines
}

func nginx(prefixes []string) []string {
	var lines []string
	for _, p := range prefixes {
		if strings.Contains(p, ":") {
			continue
		}
		lines = append(lines, "deny "+p+";")
	}
	return lines
}

func writeQualityReport(out string, ips []IPRecord, asns []ASNRecord) error {
	body := fmt.Sprintf(`# Quality Report

- IP records: %d
- ASN records: %d
- Sources: official IANA CSV registries
- Policy profiles: data-policy, edge-drop, lab-allow
- Config outputs: nftables, ipset, nginx
- MMDB explain database: not emitted by this implementation yet; JSONL explain lookup is available.
`, len(ips), len(asns))
	return os.WriteFile(filepath.Join(out, "quality-report.md"), []byte(body), 0o644)
}

func writeChecksums(root string) error {
	var files []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Base(path) == "checksums.txt" {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(files)
	var lines []string
	for _, path := range files {
		sum, err := checksum(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		lines = append(lines, sum+"  "+filepath.ToSlash(rel))
	}
	return writeLines(filepath.Join(root, "checksums.txt"), lines)
}

func checksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func boolString(v BoolValue) string {
	if v == nil {
		return "null"
	}
	if *v {
		return "true"
	}
	return "false"
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
