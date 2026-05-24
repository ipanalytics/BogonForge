package bogonforge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

func Diff(previous, current string) (ImpactDiff, error) {
	prev, err := LoadIPRecords(filepath.Join(previous, "bogonforge.jsonl.gz"))
	if err != nil {
		return ImpactDiff{}, err
	}
	cur, err := LoadIPRecords(filepath.Join(current, "bogonforge.jsonl.gz"))
	if err != nil {
		return ImpactDiff{}, err
	}
	prevMap := map[string]IPRecord{}
	for _, r := range prev {
		prevMap[r.Prefix] = r
	}
	var changed []string
	for _, r := range cur {
		old, ok := prevMap[r.Prefix]
		if !ok || !sameJSON(old, r) {
			changed = append(changed, r.Prefix)
		}
	}
	sort.Strings(changed)
	impact := ImpactDiff{
		SemanticChanges: len(changed),
		ProfileImpacts: map[string][]string{
			"data-policy": changed,
			"edge-drop":   intersect(changed, EdgeDrop(cur)),
			"lab-allow":   intersect(changed, LabAllow(cur)),
		},
	}
	if len(changed) > 0 {
		impact.DownstreamRebuildRecommended = []string{"GeoForge", "Blackroute", "ASNForge", "PrefixLint", "IntelMerge"}
	}
	return impact, nil
}

func WriteDiff(previous, current string) error {
	impact, err := Diff(previous, current)
	if err != nil {
		return err
	}
	return writePrettyJSON(filepath.Join(current, "impact-diff.json"), impact)
}

func sameJSON(a, b any) bool {
	aa, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(aa) == string(bb)
}

func intersect(a, b []string) []string {
	set := map[string]bool{}
	for _, v := range b {
		set[v] = true
	}
	var out []string
	for _, v := range a {
		if set[v] {
			out = append(out, v)
		}
	}
	return out
}

func PathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
