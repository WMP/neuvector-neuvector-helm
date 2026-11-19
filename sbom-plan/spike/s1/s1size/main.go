// s1size: measure gob+gzip size of a scan report (as written to Consul KV) for several variants.
package main

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

const limit = 512 * 1024

func sizes(r *share.ScanResult) (gobN, gzN int, err error) {
	report := share.CLUSScanReport{ScannedAt: time.Now().UTC(), ScanResult: *r}
	var buf bytes.Buffer
	if err = gob.NewEncoder(&buf).Encode(&report); err != nil {
		return
	}
	return buf.Len(), len(utils.GzipBytes(buf.Bytes())), nil
}

// variant filters a deep copy of the result.
func variant(data []byte, f func(r *share.ScanResult)) (*share.ScanResult, error) {
	var r share.ScanResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	f(&r)
	return &r, nil
}

func keep(r *share.ScanResult, all bool, fn func(m *share.ScanModule)) {
	var out []*share.ScanModule
	for _, m := range r.Modules {
		if all || m.Origin == "" {
			fn(m)
			out = append(out, m)
		}
	}
	r.Modules = out
}

func run(data []byte) error {
	vs := []struct {
		name string
		f    func(r *share.ScanResult)
	}{
		{"baseline", func(r *share.ScanResult) {
			keep(r, false, func(m *share.ScanModule) { m.Purl, m.Licenses, m.Origin = "", nil, "" })
		}},
		{"nv+purl+lic", func(r *share.ScanResult) { keep(r, false, func(*share.ScanModule) {}) }},
		{"full", func(r *share.ScanResult) { keep(r, true, func(*share.ScanModule) {}) }},
		{"full-noCPE", func(r *share.ScanResult) { keep(r, true, func(m *share.ScanModule) { m.CPEs = nil }) }},
		{"full-novuls", func(r *share.ScanResult) {
			keep(r, true, func(m *share.ScanModule) { m.Vuls = nil })
			r.Vuls = nil
		}},
	}
	for _, v := range vs {
		r, err := variant(data, v.f)
		if err != nil {
			return err
		}
		g, z, err := sizes(r)
		if err != nil {
			return err
		}
		fmt.Printf("%-12s modules=%d vuls=%d gob=%d gzip=%d limit%%=%.1f\n", v.name, len(r.Modules), len(r.Vuls), g, z, 100*float64(z)/limit)
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: s1size <augmented_result.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err == nil {
		err = run(data)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
