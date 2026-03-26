// Package tui provides an interactive terminal dashboard for syscalld.
package tui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/loudmumble/syscalld/core"
)

// view constants
const (
	viewStream = iota
	viewStats
	viewConfig
	viewAlerts
)

var viewNames = []string{"Stream", "Stats", "Config", "Alerts"}

// eventEntry is a timestamped event line.
type eventEntry struct {
	ts      time.Time
	kind    string
	summary string
}

// tickMsg drives the refresh timer.
type tickMsg time.Time

// eventMsg delivers new events from the sensor goroutine.
type eventMsg struct{ events []core.Event }

// styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF87")).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#00FF87")).
			Padding(0, 2)

	tabActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF87")).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(lipgloss.Color("#00FF87")).
			Padding(0, 1)

	tabInactive = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666")).
			Padding(0, 1)

	sensorActive = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF87")).Bold(true)

	sensorInactive = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5F57")).Bold(true)

	kindStyles = map[string]lipgloss.Style{
		"syscall":    lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")),
		"process":    lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87")),
		"filesystem": lipgloss.NewStyle().Foreground(lipgloss.Color("#87CEEB")),
		"network":    lipgloss.NewStyle().Foreground(lipgloss.Color("#FF87D7")),
		"memory":     lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500")),
		"module":     lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F57")),
		"dns":        lipgloss.NewStyle().Foreground(lipgloss.Color("#9B59B6")),
	}

	alertStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F57")).Bold(true)
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
)

// Model is the bubbletea model for the sensor dashboard.
type Model struct {
	view     int
	width    int
	height   int
	viewport viewport.Model
	spinner  spinner.Model

	manager  *core.SensorManager
	mu       sync.Mutex
	events   []eventEntry
	counts   map[string]int
	alerts   []string
	maxLines int

	activeView int
}

// NewModel creates a Model bound to an already-configured SensorManager.
func NewModel(mgr *core.SensorManager) *Model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87"))

	m := &Model{
		manager:    mgr,
		spinner:    sp,
		counts:     make(map[string]int),
		maxLines:   500,
		activeView: viewStream,
	}

	// Subscribe to all event types and buffer them.
	mgr.OnAny(func(e core.Event) {
		m.mu.Lock()
		defer m.mu.Unlock()
		kind := e.GetEventType()
		m.counts[kind]++
		entry := eventEntry{
			ts:      time.Now(),
			kind:    kind,
			summary: formatEvent(e),
		}
		m.events = append(m.events, entry)
		if len(m.events) > m.maxLines {
			m.events = m.events[len(m.events)-m.maxLines:]
		}
	})

	return m
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		tick(),
	)
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport = viewport.New(msg.Width-2, msg.Height-8)

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab", "right", "l":
			m.activeView = (m.activeView + 1) % len(viewNames)
		case "shift+tab", "left", "h":
			m.activeView = (m.activeView - 1 + len(viewNames)) % len(viewNames)
		case "1":
			m.activeView = viewStream
		case "2":
			m.activeView = viewStats
		case "3":
			m.activeView = viewConfig
		case "4":
			m.activeView = viewAlerts
		}
		if m.activeView == viewStream {
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}

	case tickMsg:
		return m, tick()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

// View implements tea.Model.
func (m *Model) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("⚡ EBPF-SENSORS DASHBOARD") + "\n")

	// Tabs
	tabs := make([]string, len(viewNames))
	for i, name := range viewNames {
		if i == m.activeView {
			tabs[i] = tabActive.Render(fmt.Sprintf("%d:%s", i+1, name))
		} else {
			tabs[i] = tabInactive.Render(fmt.Sprintf("%d:%s", i+1, name))
		}
	}
	b.WriteString(strings.Join(tabs, " ") + "\n\n")

	switch m.activeView {
	case viewStream:
		b.WriteString(m.renderStream())
	case viewStats:
		b.WriteString(m.renderStats())
	case viewConfig:
		b.WriteString(m.renderConfig())
	case viewAlerts:
		b.WriteString(m.renderAlerts())
	}

	b.WriteString("\n" + dimStyle.Render("Tab/1-4: switch view  •  ↑/↓: scroll  •  q: quit"))
	return b.String()
}

func (m *Model) renderStream() string {
	m.mu.Lock()
	events := make([]eventEntry, len(m.events))
	copy(events, m.events)
	m.mu.Unlock()

	var lines []string
	for _, e := range events {
		style, ok := kindStyles[e.kind]
		if !ok {
			style = lipgloss.NewStyle()
		}
		ts := dimStyle.Render(e.ts.Format("15:04:05.000"))
		kind := style.Render(fmt.Sprintf("%-12s", e.kind))
		lines = append(lines, fmt.Sprintf("%s %s %s", ts, kind, e.summary))
	}

	content := strings.Join(lines, "\n")
	m.viewport.SetContent(content)
	m.viewport.GotoBottom()
	return m.viewport.View()
}

func (m *Model) renderStats() string {
	m.mu.Lock()
	counts := make(map[string]int, len(m.counts))
	for k, v := range m.counts {
		counts[k] = v
	}
	m.mu.Unlock()

	var b strings.Builder
	b.WriteString("  Event Counts by Sensor Type\n")
	b.WriteString("  " + strings.Repeat("─", 40) + "\n")
	total := 0
	for _, sensor := range []string{"syscall", "process", "filesystem", "network", "memory", "module", "dns"} {
		n := counts[sensor]
		total += n
		style, _ := kindStyles[sensor]
		bar := strings.Repeat("█", min(n/10, 30))
		b.WriteString(fmt.Sprintf("  %-12s %s %s %d\n",
			style.Render(sensor), dimStyle.Render(bar), style.Render(""), n))
	}
	b.WriteString("  " + strings.Repeat("─", 40) + "\n")
	b.WriteString(fmt.Sprintf("  %-12s %d\n", "TOTAL", total))
	return b.String()
}

func (m *Model) renderConfig() string {
	sensors := m.manager.SensorNames()
	var b strings.Builder
	b.WriteString("  Active Sensors\n")
	b.WriteString("  " + strings.Repeat("─", 40) + "\n")
	for _, name := range sensors {
		status := sensorActive.Render("● RUNNING")
		b.WriteString(fmt.Sprintf("  %-12s  %s\n", name, status))
	}
	b.WriteString("\n  " + dimStyle.Render("Sensor configuration managed via ~/.syscalld/config.yaml"))
	return b.String()
}

func (m *Model) renderAlerts() string {
	m.mu.Lock()
	alerts := make([]string, len(m.alerts))
	copy(alerts, m.alerts)
	m.mu.Unlock()

	if len(alerts) == 0 {
		return "  " + dimStyle.Render("No alerts triggered.")
	}
	var b strings.Builder
	b.WriteString("  Recent Alerts\n")
	b.WriteString("  " + strings.Repeat("─", 40) + "\n")
	for _, a := range alerts {
		b.WriteString(alertStyle.Render("  ⚠ " + a + "\n"))
	}
	return b.String()
}

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func formatEvent(e core.Event) string {
	return fmt.Sprintf("%+v", e)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
