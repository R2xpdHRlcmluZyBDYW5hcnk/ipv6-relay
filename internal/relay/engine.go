package relay

// Engine is a single-goroutine event loop. All mutations of shared relay
// state (the interfaces map, address caches, mirrored-neighbor tracking,
// ...) are executed as closures posted to this loop, so none of that state
// needs its own locking - only one goroutine (the one running Run) ever
// touches it. Socket readers, timers and netlink subscriptions all run in
// their own goroutines and communicate purely by posting closures here.
type Engine struct {
	events chan func()
}

// NewEngine creates an Engine with a reasonably sized backlog so that a
// short burst of packets/netlink events never blocks the sender goroutines.
func NewEngine() *Engine {
	return &Engine{events: make(chan func(), 1024)}
}

// Post schedules f to run on the engine goroutine. Safe to call from any
// goroutine, including from within the engine goroutine itself.
func (e *Engine) Post(f func()) {
	e.events <- f
}

// Run processes posted closures until the channel is closed. It never
// returns during normal operation.
func (e *Engine) Run() {
	for f := range e.events {
		f()
	}
}

// Eng is the single global engine instance used by the whole daemon.
var Eng = NewEngine()
