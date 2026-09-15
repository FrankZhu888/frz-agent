package main

import "testing"

func TestPickStyle(t *testing.T) {
	cases := []struct {
		name      string
		colorfgbg string
		want      string
	}{
		{"COLORFGBG light bg -> github", "0;15", "github"},
		{"COLORFGBG bg=7 -> github", "15;7", "github"},
		{"COLORFGBG dark -> monokai", "15;0", "monokai"},
		{"unset -> monokai (dark default)", "", "monokai"},
		{"COLORFGBG garbage -> monokai", "garbage", "monokai"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("COLORFGBG", c.colorfgbg)
			if got := pickStyle(); got != c.want {
				t.Errorf("pickStyle() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestSupportsTrueColor(t *testing.T) {
	cases := []struct{ env, want string }{
		{"truecolor", "true"}, {"24bit", "true"}, {"TRUECOLOR", "true"},
		{"", "false"}, {"yes", "false"}, {"256color", "false"},
	}
	for _, c := range cases {
		t.Setenv("COLORTERM", c.env)
		if got := supportsTrueColor(); got != (c.want == "true") {
			t.Errorf("COLORTERM=%q: supportsTrueColor() = %v, want %s", c.env, got, c.want)
		}
	}
}
