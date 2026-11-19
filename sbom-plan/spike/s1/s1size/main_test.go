package main

import (
	"encoding/json"
	"testing"

	"github.com/neuvector/neuvector/share"
)

func TestSizes(t *testing.T) {
	r := &share.ScanResult{Modules: []*share.ScanModule{
		{Name: "a", Version: "1", Purl: "pkg:deb/debian/a@1"},
		{Name: "b", Version: "2", Purl: "pkg:npm/b@2", Origin: "syft", Licenses: []string{"MIT"}},
	}}
	data, _ := json.Marshal(r)
	var sz [2]int
	for i, origin := range []bool{false, true} {
		rr, err := variant(data, func(r *share.ScanResult) { keep(r, origin, func(*share.ScanModule) {}) })
		if err != nil {
			t.Fatal(err)
		}
		if _, sz[i], err = sizes(rr); err != nil || sz[i] == 0 {
			t.Fatal(err, sz[i])
		}
	}
	if sz[0] > sz[1] {
		t.Fatal("baseline > full", sz)
	}
	if err := run(data); err != nil {
		t.Fatal(err)
	}
}
