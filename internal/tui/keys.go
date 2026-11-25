package tui

import (
	"strings"

	"charm.land/bubbles/v2/key"
)

type reviewKeyMap struct {
	Move, Open, Step, Search, Filter       key.Binding
	Tabs, Locations, Copy, Handoff, Export key.Binding
	Notes, Reminder, Help, Back, Quit      key.Binding
}

var reviewKeys = reviewKeyMap{
	Move:      key.NewBinding(key.WithKeys("up", "down", "j", "k"), key.WithHelp("↑↓ j k", "move")),
	Open:      key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open finding")),
	Step:      key.NewBinding(key.WithKeys("[", "]"), key.WithHelp("[ ]", "prev / next finding")),
	Search:    key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
	Filter:    key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "minimum severity")),
	Tabs:      key.NewBinding(key.WithKeys("1", "2", "3"), key.WithHelp("1 2 3", "switch tabs")),
	Locations: key.NewBinding(key.WithKeys("l"), key.WithHelp("l", "evidence locations")),
	Copy:      key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "copy file:line")),
	Handoff:   key.NewBinding(key.WithKeys("h"), key.WithHelp("h", "handoff brief")),
	Export:    key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "export report")),
	Notes:     key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "session notes")),
	Reminder:  key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "5-minute reminder")),
	Help:      key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "keys")),
	Back:      key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
	Quit:      key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
}

func (k reviewKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Open, k.Search, k.Filter, k.Handoff, k.Help, k.Quit}
}

func (k reviewKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Move, k.Open, k.Step, k.Search, k.Filter},
		{k.Tabs, k.Locations, k.Copy, k.Handoff, k.Export},
		{k.Notes, k.Reminder, k.Help, k.Back, k.Quit},
	}
}

func keysMarkdown() string {
	var b strings.Builder
	b.WriteString("## Keys\n\n")
	for _, column := range reviewKeys.FullHelp() {
		for _, binding := range column {
			b.WriteString("- `" + binding.Help().Key + "`  " + binding.Help().Desc + "\n")
		}
	}
	return b.String()
}
