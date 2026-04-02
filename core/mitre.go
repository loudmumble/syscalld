package core

// MITRETag carries MITRE ATT&CK technique information for a kernel event.
type MITRETag struct {
	TechniqueID    string
	SubTechniqueID string
	Name           string
	Tactic         string
}

// HookMITREMap maps eBPF hook names to their MITRE ATT&CK technique tags.
var HookMITREMap = map[string]MITRETag{
	"sched_process_exec": {
		TechniqueID:    "T1059",
		SubTechniqueID: "T1059.004",
		Name:           "Unix Shell",
		Tactic:         "Execution",
	},
	"sched_process_exit": {
		TechniqueID:    "T1057",
		SubTechniqueID: "",
		Name:           "Process Discovery",
		Tactic:         "Discovery",
	},
	"tcp_v4_connect": {
		TechniqueID:    "T1071",
		SubTechniqueID: "T1071.001",
		Name:           "Web Protocols",
		Tactic:         "Command and Control",
	},
	"tcp_v6_connect": {
		TechniqueID:    "T1071",
		SubTechniqueID: "T1071.001",
		Name:           "Web Protocols",
		Tactic:         "Command and Control",
	},
	"openat": {
		TechniqueID:    "T1083",
		SubTechniqueID: "",
		Name:           "File and Directory Discovery",
		Tactic:         "Discovery",
	},
	"mmap": {
		TechniqueID:    "T1055",
		SubTechniqueID: "T1055.009",
		Name:           "Proc Memory",
		Tactic:         "Defense Evasion",
	},
	"do_init_module": {
		TechniqueID:    "T1547",
		SubTechniqueID: "T1547.006",
		Name:           "Kernel Modules and Extensions",
		Tactic:         "Persistence",
	},
	"sys_enter": {
		TechniqueID:    "T1106",
		SubTechniqueID: "",
		Name:           "Native API",
		Tactic:         "Execution",
	},
	"dns_query": {
		TechniqueID:    "T1071",
		SubTechniqueID: "T1071.004",
		Name:           "DNS",
		Tactic:         "Command and Control",
	},
}
