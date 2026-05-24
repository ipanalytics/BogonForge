package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/alx/bogonforge/internal/bogonforge"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bogonforge:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "build":
		fs := flag.NewFlagSet("build", flag.ExitOnError)
		out := fs.String("out", "release/current", "output release directory")
		ipv4 := fs.String("ipv4-url", bogonforge.DefaultIPv4URL, "IANA IPv4 CSV URL")
		ipv6 := fs.String("ipv6-url", bogonforge.DefaultIPv6URL, "IANA IPv6 CSV URL")
		asn := fs.String("asn-url", bogonforge.DefaultASNURL, "IANA ASN CSV URL")
		_ = fs.Parse(args[1:])
		return bogonforge.Build(bogonforge.BuildOptions{Out: *out, IPv4URL: *ipv4, IPv6URL: *ipv6, ASNURL: *asn})
	case "inspect", "explain":
		db, rest, err := extractDB(args[1:])
		if err != nil {
			return err
		}
		if len(rest) != 1 {
			return fmt.Errorf("%s requires an IP address", args[0])
		}
		records, err := bogonforge.LoadIPRecords(db)
		if err != nil {
			return err
		}
		rec, ok, err := bogonforge.Inspect(records, rest[0])
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("IP: %s\nSpecial-use: false\n", rest[0])
			return nil
		}
		printExplain(rest[0], rec)
		return nil
	case "export":
		fs := flag.NewFlagSet("export", flag.ExitOnError)
		profile := fs.String("profile", "data-policy", "profile name")
		format := fs.String("format", "json", "json, txt, nftables, ipset, nginx")
		db := fs.String("db", "release/current/bogonforge.jsonl.gz", "compiled JSONL gzip artifact")
		_ = fs.Parse(args[1:])
		records, err := bogonforge.LoadIPRecords(*db)
		if err != nil {
			return err
		}
		return export(records, *profile, *format)
	case "diff":
		if len(args) != 3 {
			return fmt.Errorf("diff requires previous and current release directories")
		}
		impact, err := bogonforge.Diff(args[1], args[2])
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(impact, "", "  ")
		fmt.Println(string(b))
		return nil
	case "validate":
		strict, rest := extractStrict(args[1:])
		if len(rest) != 1 {
			return fmt.Errorf("validate requires a release directory")
		}
		return bogonforge.Validate(rest[0], strict)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func extractStrict(args []string) (bool, []string) {
	strict := false
	var rest []string
	for _, arg := range args {
		if arg == "--strict" {
			strict = true
			continue
		}
		rest = append(rest, arg)
	}
	return strict, rest
}

func extractDB(args []string) (string, []string, error) {
	db := "release/current/bogonforge.jsonl.gz"
	var rest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("--db requires a value")
			}
			db = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "--db=") {
				db = strings.TrimPrefix(args[i], "--db=")
				continue
			}
			rest = append(rest, args[i])
		}
	}
	return db, rest, nil
}

func export(records []bogonforge.IPRecord, profile, format string) error {
	switch profile {
	case "edge-drop":
		lines := bogonforge.EdgeDrop(records)
		return printList(lines, format)
	case "lab-allow":
		return printList(bogonforge.LabAllow(records), format)
	case "data-policy":
		b, _ := json.MarshalIndent(records, "", "  ")
		fmt.Println(string(b))
		return nil
	default:
		return fmt.Errorf("unknown profile %q", profile)
	}
}

func printList(lines []string, format string) error {
	switch format {
	case "txt":
		fmt.Println(strings.Join(lines, "\n"))
	case "json":
		b, _ := json.MarshalIndent(lines, "", "  ")
		fmt.Println(string(b))
	case "nftables":
		fmt.Println("table inet bogonforge {")
		fmt.Println("  set edge_drop {")
		fmt.Println("    type inet_addr")
		fmt.Println("    flags interval")
		fmt.Println("    elements = {")
		for i, p := range lines {
			sep := ","
			if i == len(lines)-1 {
				sep = ""
			}
			fmt.Println("      " + p + sep)
		}
		fmt.Println("    }")
		fmt.Println("  }")
		fmt.Println("}")
	case "ipset":
		fmt.Println("create bogonforge_edge_drop hash:net family inet hashsize 1024 maxelem 65536")
		for _, p := range lines {
			if !strings.Contains(p, ":") {
				fmt.Println("add bogonforge_edge_drop " + p)
			}
		}
	case "nginx":
		for _, p := range lines {
			if !strings.Contains(p, ":") {
				fmt.Println("deny " + p + ";")
			}
		}
	default:
		return fmt.Errorf("unknown format %q", format)
	}
	return nil
}

func printExplain(ip string, rec bogonforge.IPRecord) {
	fmt.Printf("IP: %s -> %s\n", ip, rec.Prefix)
	fmt.Printf("Class: %s (%s, %s)\n", rec.Class, strings.Join(rec.Facts.RFC, ", "), rec.Facts.Source)
	fmt.Printf("Name: %s\n", rec.Name)
	fmt.Printf("Facts: globally_reachable=%s forwardable=%s source_valid=%s destination_valid=%s reserved_by_protocol=%s\n",
		boolValue(rec.Facts.GloballyReachable),
		boolValue(rec.Facts.Forwardable),
		boolValue(rec.Facts.SourceValid),
		boolValue(rec.Facts.DestinationValid),
		boolValue(rec.Facts.ReservedByProtocol),
	)
	fmt.Printf("Policy: %s\n", strings.Join(rec.DatasetPolicy, ", "))
}

func boolValue(v bogonforge.BoolValue) string {
	if v == nil {
		return "null"
	}
	if *v {
		return "true"
	}
	return "false"
}

func usage() {
	fmt.Println(`bogonforge build   --out release/current
bogonforge inspect 192.0.2.1 --db release/current/bogonforge.jsonl.gz
bogonforge explain 100.64.1.1 --db release/current/bogonforge.jsonl.gz
bogonforge export  --profile edge-drop --format nftables --db release/current/bogonforge.jsonl.gz
bogonforge diff    release/previous release/current
bogonforge validate release/current --strict`)
}
