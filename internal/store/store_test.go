package store

import (
	"context"
	"testing"
)

func TestLegacySiteUpgrade(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// A site as stored by the first release (block_countries, no geo/challenge).
	_, err = st.db.Exec(`INSERT INTO sites(name, data, enabled, created_at, updated_at) VALUES('old', '{"hosts":["a.test"],"upstreams":["http://127.0.0.1:1"],"mode":"block","block_countries":["RU"]}', 1, 0, 0)`)
	if err != nil {
		t.Fatal(err)
	}
	sites, err := st.ListSites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := sites[0]
	if s.Geo.Mode != "block" || len(s.Geo.Rules) != 1 || s.Geo.Rules[0] != "RU" {
		t.Fatalf("geo not migrated: %+v", s.Geo)
	}
	if s.Challenge.Mode != "off" || s.Challenge.ExemptPaths == nil || s.BlockCountries != nil {
		t.Fatalf("defaults missing: %+v", s.Challenge)
	}
	if err := s.Normalize(); err != nil {
		t.Fatal(err)
	}
}
