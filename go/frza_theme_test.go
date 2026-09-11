package main

import "testing"

func TestPickStyle(t *testing.T) {
	cases := []struct {
		name      string
		theme     string
		colorfgbg string
		want      string
	}{
		{"FRZA_THEME=dark wins", "dark", "0;15", "monokai"},
		{"FRZA_THEME=light wins", "light", "", "github"},
		{"COLORFGBG light bg -> github", "", "0;15", "github"},
		{"COLORFGBG bg=7 -> github", "", "15;7", "github"},
		{"COLORFGBG dark -> monokai", "", "15;0", "monokai"},
		{"unset everything -> monokai (dark default)", "", "", "monokai"},
		{"COLORFGBG garbage -> monokai", "", "garbage", "monokai"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("FRZA_THEME", c.theme)
			t.Setenv("COLORFGBG", c.colorfgbg)
			if got := pickStyle(); got != c.want {
				t.Errorf("pickStyle() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestDetectColorSupportThemeNone(t *testing.T) {
	t.Setenv("FRZA_FORCE_COLOR", "")
	t.Setenv("NO_COLOR", "")
	t.Setenv("FRZA_THEME", "none")
	if detectColorSupport() {
		t.Errorf("FRZA_THEME=none should disable color")
	}
	t.Setenv("FRZA_THEME", "dark")
	// cannot assert tty-dependent true case; just ensure no panic and bool type
	_ = detectColorSupport()
}
