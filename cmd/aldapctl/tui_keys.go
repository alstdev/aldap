package main

import "github.com/charmbracelet/bubbles/key"

// tab is one TUI tab (SPEC §8).
type tab int

const (
	tabStatus tab = iota
	tabUpstreams
	tabProfiles
	tabLocks
	tabEvents
	tabIndicators
	tabConfig
	numTabs
)

var tabNames = [numTabs]string{"Status", "Upstreams", "Profiles", "Locks", "Events", "Indicators", "Config"}

func (t tab) String() string { return tabNames[t] }

func bind(keys []string, label, desc string) key.Binding {
	return key.NewBinding(key.WithKeys(keys...), key.WithHelp(label, desc))
}

// Global keys (Bubble Tea conventions: q quits, ? toggles the help).
var (
	keyQuit     = bind([]string{"q", "ctrl+c"}, "q", "quit")
	keyHelp     = bind([]string{"?"}, "?", "show / hide this help")
	keyNext     = bind([]string{"tab", "right"}, "tab →", "next tab")
	keyPrev     = bind([]string{"shift+tab", "left"}, "S-tab ←", "previous tab")
	keyJump     = bind([]string{"1", "2", "3", "4", "5", "6", "7"}, "1-7", "go to a tab")
	keyUp       = bind([]string{"up", "k"}, "↑ k", "move / scroll up")
	keyDown     = bind([]string{"down", "j"}, "↓ j", "move / scroll down")
	keyPgUp     = bind([]string{"pgup", "ctrl+b"}, "pgup", "page up")
	keyPgDown   = bind([]string{"pgdown", "ctrl+f"}, "pgdn", "page down")
	keyTop      = bind([]string{"home", "g"}, "g home", "first line")
	keyBottom   = bind([]string{"end", "G"}, "G end", "last line / newest")
	keyRefresh  = bind([]string{"r"}, "r", "refresh now")
	keyReload   = bind([]string{"R"}, "R", "reload config (confirm)")
	keyLockdown = bind([]string{"d"}, "d", "lockdown on/off (confirm)")
	keySync     = bind([]string{"s"}, "s", "replica sync (confirm)")
	keyLearn    = bind([]string{"b"}, "b", "baseline learn (confirm)")
	keyUnlock   = bind([]string{"u"}, "u", "unlock selected (confirm)")
	keyLock     = bind([]string{"l"}, "l", "lock ip/account (confirm)")
	keyLockInd  = bind([]string{"l"}, "l", "lock selected (confirm)")
	keyPause    = bind([]string{" ", "p"}, "space p", "pause / resume")
	keyFilter   = bind([]string{"f"}, "f", "filter type/profile/ip")
	keySearch   = bind([]string{"/"}, "/", "search text")
	keyClear    = bind([]string{"c"}, "c", "clear filter and search")
	keyEdit     = bind([]string{"e"}, "e", "edit in $EDITOR")
	keyValidate = bind([]string{"v"}, "v", "validate the draft")
	keyApply    = bind([]string{"a"}, "a", "apply draft (confirm)")
	keyDiscard  = bind([]string{"x"}, "x", "discard the draft")
	keyYes      = bind([]string{"y", "Y"}, "y", "confirm the action")
	keyNo       = bind([]string{"n", "N", "esc"}, "n esc", "cancel the action")
	keySubmit   = bind([]string{"enter"}, "enter", "submit the input")
	keyCancel   = bind([]string{"esc"}, "esc", "cancel the input")
)

// helpSection is one block of the help screen.
type helpSection struct {
	title string
	keys  []key.Binding
}

var globalKeys = []key.Binding{keyQuit, keyHelp, keyNext, keyPrev, keyJump, keyUp, keyDown, keyPgUp, keyPgDown, keyTop, keyBottom, keyRefresh, keyReload}

// tabKeys are the keys of each tab beyond the global ones.
var tabKeys = map[tab][]key.Binding{
	tabStatus:     {keyLockdown},
	tabProfiles:   {keySync, keyLearn},
	tabLocks:      {keyUnlock, keyLock},
	tabEvents:     {keyPause, keyFilter, keySearch, keyClear},
	tabIndicators: {keyLockInd},
	tabConfig:     {keyEdit, keyValidate, keyApply, keyDiscard},
}

// helpLayout is the help screen: global keys and prompts on the left,
// the tab keys on the right, so it fits 80×24.
func helpLayout() (left, right []helpSection) {
	left = []helpSection{{"Global", globalKeys}, {"Prompts", []key.Binding{keyYes, keyNo, keySubmit, keyCancel}}}
	for t := range numTabs {
		if ks := tabKeys[t]; len(ks) > 0 {
			right = append(right, helpSection{t.String(), ks})
		}
	}
	return left, right
}
