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

// styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF87")).
			Padding(0, 1)

	brandBorder = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF87")).
			BorderStyle(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#00FF87")).
			Padding(0, 2)

	tabActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF87")).
			Background(lipgloss.Color("#1a1a2e")).
			Padding(0, 2)

	tabInactive = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666")).
			Padding(0, 2)

	sensorActive = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF87")).Bold(true)

	sensorInactive = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF5F57")).Bold(true)

	kindStyles = map[string]lipgloss.Style{
		"syscall": lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")),
		"process": lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87")),
		"file":    lipgloss.NewStyle().Foreground(lipgloss.Color("#87CEEB")),
		"network": lipgloss.NewStyle().Foreground(lipgloss.Color("#FF87D7")),
		"memory":  lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500")),
		"module":  lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F57")),
		"dns":     lipgloss.NewStyle().Foreground(lipgloss.Color("#9B59B6")),
		"canary":  lipgloss.NewStyle().Foreground(lipgloss.Color("#444444")),
	}

	alertStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F57")).Bold(true)
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
	accentStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87"))
	headerStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF"))
	dividerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#333333"))
)

// Model is the bubbletea model for the sensor dashboard.
type Model struct {
	width    int
	height   int
	viewport viewport.Model
	spinner  spinner.Model

	manager   *core.SensorManager
	startTime time.Time
	mu        sync.Mutex
	events    []eventEntry
	counts    map[string]int
	total     int
	alerts    []string
	maxLines  int

	activeView int
}

// NewModel creates a Model bound to an already-configured SensorManager.
func NewModel(mgr *core.SensorManager) *Model {
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF87"))

	m := &Model{
		manager:    mgr,
		startTime:  time.Now(),
		spinner:    sp,
		counts:     make(map[string]int),
		maxLines:   1000,
		activeView: viewStream,
	}

	// Subscribe to all event types and buffer them.
	mgr.OnAny(func(e core.Event) {
		kind := e.GetEventType()

		m.mu.Lock()
		defer m.mu.Unlock()
		m.counts[kind]++
		m.total++

		// Don't show canary heartbeats in the stream — they're internal.
		if kind == "canary" {
			return
		}

		entry := eventEntry{
			ts:      time.Now(),
			kind:    kind,
			summary: formatEventSummary(e),
		}
		m.events = append(m.events, entry)
		if len(m.events) > m.maxLines {
			m.events = m.events[len(m.events)-m.maxLines:]
		}
	})

	return m
}

// AddAlert appends a formatted alert to the alerts tab. Safe for concurrent use.
func (m *Model) AddAlert(t time.Time, message string, severity string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	line := fmt.Sprintf("[%s] [%s] %s", t.Format("15:04:05"), severity, message)
	m.alerts = append(m.alerts, line)
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
		// Reserve 6 lines: title(2) + tabs(1) + blank(1) + statusbar(2)
		m.viewport = viewport.New(msg.Width-4, msg.Height-6)

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
	if m.width == 0 {
		return "Initializing..."
	}

	var b strings.Builder

	// Title bar
	b.WriteString(brandBorder.Render("syscalld") + "  ")
	b.WriteString(dimStyle.Render("kernel sensor dashboard"))
	b.WriteString("\n")

	// Tabs
	tabs := make([]string, len(viewNames))
	for i, name := range viewNames {
		label := fmt.Sprintf(" %d %s ", i+1, name)
		if i == m.activeView {
			tabs[i] = tabActive.Render(label)
		} else {
			tabs[i] = tabInactive.Render(label)
		}
	}
	b.WriteString(strings.Join(tabs, "") + "\n")
	b.WriteString(dividerStyle.Render(strings.Repeat("─", m.width)) + "\n")

	// Content
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

	// Status bar
	b.WriteString("\n")
	b.WriteString(dividerStyle.Render(strings.Repeat("─", m.width)) + "\n")
	b.WriteString(m.renderStatusBar())

	return b.String()
}

func (m *Model) renderStream() string {
	m.mu.Lock()
	events := make([]eventEntry, len(m.events))
	copy(events, m.events)
	m.mu.Unlock()

	if len(events) == 0 {
		return dimStyle.Render("  Waiting for events...")
	}

	var lines []string
	for _, e := range events {
		style, ok := kindStyles[e.kind]
		if !ok {
			style = lipgloss.NewStyle()
		}
		ts := dimStyle.Render(e.ts.Format("15:04:05.000"))
		kind := style.Render(fmt.Sprintf("%-12s", e.kind))
		lines = append(lines, fmt.Sprintf("  %s  %s  %s", ts, kind, e.summary))
	}

	content := strings.Join(lines, "\n")
	m.viewport.SetContent(content)
	m.viewport.GotoBottom()
	return m.viewport.View()
}

func (m *Model) renderStats() string {
	m.mu.Lock()
	counts := make(map[string]int, len(m.counts))
	total := m.total
	for k, v := range m.counts {
		counts[k] = v
	}
	m.mu.Unlock()

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("  " + headerStyle.Render("Event Counts by Sensor Type") + "\n\n")

	// Find max for bar scaling
	maxCount := 1
	sensorTypes := []string{"syscall", "process", "file", "network", "memory", "module", "dns"}
	for _, sensor := range sensorTypes {
		if counts[sensor] > maxCount {
			maxCount = counts[sensor]
		}
	}

	barWidth := 30
	for _, sensor := range sensorTypes {
		n := counts[sensor]
		style := kindStyles[sensor]

		// Scale bar proportionally
		barLen := 0
		if maxCount > 0 && n > 0 {
			barLen = (n * barWidth) / maxCount
			if barLen == 0 {
				barLen = 1
			}
		}

		bar := style.Render(strings.Repeat("█", barLen))
		pad := strings.Repeat(" ", barWidth-barLen)
		b.WriteString(fmt.Sprintf("  %-12s  %s%s  %s\n",
			style.Render(sensor), bar, pad, dimStyle.Render(fmt.Sprintf("%d", n))))
	}

	b.WriteString("\n  " + dividerStyle.Render(strings.Repeat("─", 50)) + "\n")
	b.WriteString(fmt.Sprintf("  %-12s  %s\n",
		headerStyle.Render("TOTAL"), accentStyle.Render(fmt.Sprintf("%d events", total))))

	// Canary count
	if canary := counts["canary"]; canary > 0 {
		b.WriteString(fmt.Sprintf("  %-12s  %s\n",
			dimStyle.Render("canary"),
			dimStyle.Render(fmt.Sprintf("%d heartbeats", canary))))
	}

	// Dropped events
	dropped := m.manager.DroppedEvents()
	if dropped > 0 {
		b.WriteString(fmt.Sprintf("\n  %s  %d events lost\n",
			alertStyle.Render("BUFFER PRESSURE"), dropped))
	}

	return b.String()
}

func (m *Model) renderConfig() string {
	healths := m.manager.Healths()

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("  " + headerStyle.Render("Active Sensors") + "\n\n")
	b.WriteString(fmt.Sprintf("  %-14s  %-10s  %-10s  %-10s  %s\n",
		headerStyle.Render("SENSOR"),
		headerStyle.Render("MODE"),
		headerStyle.Render("STATUS"),
		headerStyle.Render("EVENTS"),
		headerStyle.Render("ERRORS")))
	b.WriteString("  " + dividerStyle.Render(strings.Repeat("─", 60)) + "\n")

	for _, h := range healths {
		status := sensorActive.Render("running")
		if !h.Started {
			status = sensorInactive.Render("stopped")
		}
		mode := dimStyle.Render(h.Mode)
		events := accentStyle.Render(fmt.Sprintf("%d", h.EventCount))
		errors := dimStyle.Render(fmt.Sprintf("%d", h.ErrorCount))
		if h.ErrorCount > 0 {
			errors = alertStyle.Render(fmt.Sprintf("%d", h.ErrorCount))
		}
		b.WriteString(fmt.Sprintf("  %-14s  %-10s  %-10s  %-10s  %s\n",
			h.Name, mode, status, events, errors))
	}

	b.WriteString("\n  " + dimStyle.Render("Config: ~/.syscalld/config.yaml"))
	b.WriteString("\n  " + dimStyle.Render("Manage: syscalld config show | init | preset <name>"))
	return b.String()
}

func (m *Model) renderAlerts() string {
	m.mu.Lock()
	alerts := make([]string, len(m.alerts))
	copy(alerts, m.alerts)
	m.mu.Unlock()

	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("  " + headerStyle.Render("Alert Log") + "\n\n")

	if len(alerts) == 0 {
		b.WriteString("  " + dimStyle.Render("No alerts triggered.") + "\n\n")
		b.WriteString("  " + dimStyle.Render("Alerts are configured in ~/.syscalld/config.yaml under the 'alerts' key.") + "\n")
		b.WriteString("  " + dimStyle.Render("Each rule defines an event_type, threshold_per_second, and severity.") + "\n")
		b.WriteString("  " + dimStyle.Render("Use 'syscalld config preset threat-hunting' for example alert rules.") + "\n")
		return b.String()
	}

	b.WriteString("  " + dividerStyle.Render(strings.Repeat("─", 50)) + "\n")
	for _, a := range alerts {
		b.WriteString(alertStyle.Render("  ! "+a) + "\n")
	}
	return b.String()
}

func (m *Model) renderStatusBar() string {
	uptime := time.Since(m.startTime).Truncate(time.Second)
	sensorCount := m.manager.SensorCount()

	m.mu.Lock()
	total := m.total
	m.mu.Unlock()

	dropped := m.manager.DroppedEvents()

	left := dimStyle.Render(fmt.Sprintf(
		" %s %d sensors  %s %d events  %s %s",
		m.spinner.View(), sensorCount,
		accentStyle.Render(""), total,
		dimStyle.Render("up"), uptime,
	))

	right := dimStyle.Render("Tab/1-4:view  arrows:scroll  q:quit ")

	if dropped > 0 {
		right = alertStyle.Render(fmt.Sprintf(" %d dropped ", dropped)) + "  " + right
	}

	// Pad middle
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 0 {
		gap = 0
	}

	return left + strings.Repeat(" ", gap) + right
}

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// formatEventSummary produces a concise one-line summary for each event type.
func formatEventSummary(e core.Event) string {
	switch evt := e.(type) {
	case *core.SyscallEvent:
		name := evt.SyscallName
		if name == "" {
			name = fmt.Sprintf("nr=%d", evt.SyscallNR)
		}
		return fmt.Sprintf("pid=%d comm=%s %s",
			evt.PID, evt.Comm, name)
	case *core.ProcessEvent:
		if evt.Filename != "" {
			return fmt.Sprintf("pid=%d %s %s", evt.PID, evt.Action, evt.Filename)
		}
		return fmt.Sprintf("pid=%d %s comm=%s ppid=%d",
			evt.PID, evt.Action, evt.Comm, evt.PPID)
	case *core.FileEvent:
		return fmt.Sprintf("pid=%d comm=%s %s %s",
			evt.PID, evt.Comm, evt.Operation, evt.Path)
	case *core.NetworkEvent:
		return fmt.Sprintf("pid=%d comm=%s %s %s:%d -> %s:%d",
			evt.PID, evt.Comm, evt.Protocol, evt.SAddr, evt.SPort,
			evt.DAddr, evt.DPort)
	case *core.MemoryEvent:
		return fmt.Sprintf("pid=%d comm=%s %s addr=0x%x len=%d",
			evt.PID, evt.Comm, evt.Operation, evt.Addr, evt.Length)
	case *core.ModuleEvent:
		return fmt.Sprintf("pid=%d comm=%s %s %s",
			evt.PID, evt.Comm, evt.Operation, evt.ModuleName)
	case *core.DnsEvent:
		return fmt.Sprintf("pid=%d comm=%s %s -> %s:%d",
			evt.PID, evt.Comm, evt.QueryName, evt.DestIP, evt.DestPort)
	default:
		return fmt.Sprintf("%+v", e)
	}
}
