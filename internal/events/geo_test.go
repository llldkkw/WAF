package events

import "testing"

func TestLocationMatches(t *testing.T) {
	sz := Location{Country: "CN", Region: "CN-GD", City: "Shenzhen", CityZh: "深圳"}
	cases := []struct {
		rule string
		want bool
	}{
		{"CN", true}, {"cn", true}, {"US", false},
		{"CN-GD", true}, {"CN-BJ", false},
		{"CN/深圳", true}, {"CN/Shenzhen", true}, {"CN-GD/深圳", true}, {"CN-GD/广州", false}, {"CN-BJ/深圳", false},
		{"CN/", false},
	}
	for _, c := range cases {
		if got := sz.Matches(c.rule); got != c.want {
			t.Errorf("%q: got %v want %v", c.rule, got, c.want)
		}
	}
	if (Location{}).Matches("CN") {
		t.Error("unknown location must not match")
	}
	if s := sz.String(); s != "CN-GD 深圳" {
		t.Errorf("String() = %q", s)
	}
}
