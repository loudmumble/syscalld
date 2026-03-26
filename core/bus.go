package core

import (
	"fmt"
	"os"
	"sync"
)

// EventHandler is a callback function that processes a single event.
type EventHandler func(Event)

// EventBus routes Event instances to registered typed callbacks.
// It supports per-event-type subscriptions and catch-all listeners.
// Thread-safe: handlers are stored under a mutex; emit acquires a read
// snapshot so callbacks run without holding the lock.
type EventBus struct {
	mu          sync.RWMutex
	handlers    map[string][]EventHandler
	anyHandlers []EventHandler
}

// NewEventBus creates a new EventBus ready for use.
func NewEventBus() *EventBus {
	return &EventBus{
		handlers: make(map[string][]EventHandler),
	}
}

// On registers a callback for a specific event type.
func (b *EventBus) On(eventType string, callback EventHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[eventType] = append(b.handlers[eventType], callback)
}

// OnAny registers a catch-all callback invoked for every event.
func (b *EventBus) OnAny(callback EventHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.anyHandlers = append(b.anyHandlers, callback)
}

// Emit dispatches an event to matching callbacks.
// Typed handlers are called first, then catch-all handlers.
// Exceptions in callbacks are caught and logged to avoid
// breaking the polling loop.
func (b *EventBus) Emit(event Event) {
	b.mu.RLock()
	typed := b.handlers[event.GetEventType()]
	// Copy slices under lock to avoid race
	typedCopy := make([]EventHandler, len(typed))
	copy(typedCopy, typed)
	anyCopy := make([]EventHandler, len(b.anyHandlers))
	copy(anyCopy, b.anyHandlers)
	b.mu.RUnlock()

	for _, handler := range typedCopy {
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "[EventBus] Handler error for %s: %v\n",
						event.GetEventType(), r)
				}
			}()
			handler(event)
		}()
	}

	for _, handler := range anyCopy {
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "[EventBus] Catch-all handler error: %v\n", r)
				}
			}()
			handler(event)
		}()
	}
}

// Clear removes all registered handlers.
func (b *EventBus) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers = make(map[string][]EventHandler)
	b.anyHandlers = nil
}

// HandlerCount returns the total number of registered handlers (typed + catch-all).
func (b *EventBus) HandlerCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	count := len(b.anyHandlers)
	for _, handlers := range b.handlers {
		count += len(handlers)
	}
	return count
}
