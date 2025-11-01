package metric

// Metrics contains status about runtime submodules.
type Metrics struct {
	Library  LTStatus `toml:"library"  json:"library"`
	Memory   MTStatus `toml:"memory"   json:"memory"`
	Thread   TTStatus `toml:"thread"   json:"thread"`
	Resource RTStatus `toml:"resource" json:"resource"`
	Detector DTStatus `toml:"detector" json:"detector"`
	Sysmon   SMStatus `toml:"sysmon"   json:"sysmon"`
	Watchdog WDStatus `toml:"watchdog" json:"watchdog"`
}

// LTStatus contains status about library tracker.
type LTStatus struct {
	NumModules    int64 `toml:"num_modules"    json:"num_modules"`
	NumProcedures int64 `toml:"num_procedures" json:"num_procedures"`
}

// MTStatus contains status about memory tracker.
type MTStatus struct {
	NumGlobals int64 `toml:"num_globals" json:"num_globals"`
	NumLocals  int64 `toml:"num_locals"  json:"num_locals"`
	NumBlocks  int64 `toml:"num_blocks"  json:"num_blocks"`
	NumRegions int64 `toml:"num_regions" json:"num_regions"`
	NumPages   int64 `toml:"num_pages"   json:"num_pages"`
	NumHeaps   int64 `toml:"num_heaps"   json:"num_heaps"`
}

// TTStatus contains status about thread tracker.
type TTStatus struct {
	NumThreads  int64 `toml:"num_threads"   json:"num_threads"`
	NumTLSIndex int64 `toml:"num_tls_index" json:"num_tls_index"`
	NumSuspend  int64 `toml:"num_suspend"   json:"num_suspend"`
}

// RTStatus contains status about resource tracker.
type RTStatus struct {
	NumMutexs         int64 `toml:"num_mutexs"          json:"num_mutexs"`
	NumEvents         int64 `toml:"num_events"          json:"num_events"`
	NumSemaphores     int64 `toml:"num_semaphores"      json:"num_semaphores"`
	NumWaitableTimers int64 `toml:"num_waitable_timers" json:"num_waitable_timers"`
	NumFiles          int64 `toml:"num_files"           json:"num_files"`
	NumDirectories    int64 `toml:"num_directories"     json:"num_directories"`
	NumIOCPs          int64 `toml:"num_iocps"           json:"num_iocps"`
	NumRegKeys        int64 `toml:"num_reg_keys"        json:"num_reg_keys"`
	NumSockets        int64 `toml:"num_sockets"         json:"num_sockets"`
}

// DTStatus contains status about detector.
type DTStatus struct {
	IsEnabled        bool `toml:"is_enabled"         json:"is_enabled"`
	HasDebugger      bool `toml:"has_debugger"       json:"has_debugger"`
	HasMemoryScanner bool `toml:"has_memory_scanner" json:"has_memory_scanner"`
	InSandbox        bool `toml:"in_sandbox"         json:"in_sandbox"`
	InVirtualMachine bool `toml:"in_virtual_machine" json:"in_virtual_machine"`
	InEmulator       bool `toml:"in_emulator"        json:"in_emulator"`
	IsAccelerated    bool `toml:"is_accelerated"     json:"is_accelerated"`
	SafeRank         int8 `toml:"safe_rank"          json:"safe_rank"`
}

// SMStatus contains status about sysmon.
type SMStatus struct {
	IsEnabled  bool  `toml:"is_enabled" json:"is_enabled"`
	NumNormal  int64 `toml:"num_normal"  json:"num_normal"`
	NumRecover int64 `toml:"num_recover" json:"num_recover"`
	NumPanic   int64 `toml:"num_panic"   json:"num_panic"`
}

// WDStatus contains status about watchdog.
type WDStatus struct {
	IsEnabled bool  `toml:"is_enabled" json:"is_enabled"`
	NumKick   int64 `toml:"num_kick"   json:"num_kick"`
	NumNormal int64 `toml:"num_normal" json:"num_normal"`
	NumReset  int64 `toml:"num_reset"  json:"num_reset"`
}
