package core

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"time"

	"github.com/encodeous/nylon/perf"
)

// dispatchChannelCapacity is the depth of the per-node dispatch channel. See
// NewNylon for the sizing rationale.
const dispatchChannelCapacity = 512

// dispatchDropLogInterval bounds how often the dispatch-overflow ERROR is
// journalled. A saturated loop discards functions at producer rate (hundreds
// per second under a rotation storm); one line per drop would bury the
// journal exactly when the operator needs it readable. The first drop in a
// window logs at ERROR with the running drop count; the rest count silently
// into perf.DispatchDropsTotal and surface in the next window's line.
const dispatchDropLogInterval = 10 * time.Second

// recordDispatchDrop accounts a control-plane function discarded because the
// dispatch channel was full. Called on producer goroutines, so the journal
// emission decision is made under a small lock and the write itself happens
// outside it.
func (n *Nylon) recordDispatchDrop(fun func() error) {
	perf.DispatchDropsTotal.Add(1)
	funName := runtime.FuncForPC(reflect.ValueOf(fun).Pointer()).Name()

	n.dispatchDrops.mu.Lock()
	n.dispatchDrops.window++
	now := time.Now()
	emit := now.Sub(n.dispatchDrops.lastLog) >= dispatchDropLogInterval
	if emit {
		n.dispatchDrops.lastLog = now
	}
	window := n.dispatchDrops.window
	if emit {
		n.dispatchDrops.window = 0
	}
	n.dispatchDrops.mu.Unlock()

	if n.Log == nil {
		return
	}
	if emit {
		n.Log.Error("dispatch channel is full, discarded function",
			"fun", funName, "len", len(n.DispatchChannel), "drops_in_window", window)
		return
	}
	n.Log.Debug("dispatch channel is full, discarded function", "fun", funName, "len", len(n.DispatchChannel))
}

func NewDispatchFuture[T any](n *Nylon, fun func() (T, error)) Future[T] {
	future, complete := NewFuture[T]()
	dispatch := func() error {
		value, err := fun()
		complete(value, err)
		return nil
	}
	select {
	case n.DispatchChannel <- dispatch:
	case <-n.Context.Done():
		var zero T
		complete(zero, context.Cause(n.Context))
	default:
		var zero T
		complete(zero, fmt.Errorf("dispatch channel is full"))
		n.recordDispatchDrop(dispatch)
	}
	return future
}

// Dispatch Dispatches the function to run on the main thread without waiting for it to complete
func (n *Nylon) Dispatch(fun func() error) {
	defer func() {
		if r := recover(); r != nil {
			n.Cancel(fmt.Errorf("dispatch panic: %v", r))
		}
	}()
	for {
		select {
		case n.DispatchChannel <- fun:
			return
		default:
			n.recordDispatchDrop(fun)
			return
		}
	}
}

func (n *Nylon) ScheduleTask(fun func() error, delay time.Duration) {
	time.AfterFunc(delay, func() {
		n.Dispatch(fun)
	})
}

func (n *Nylon) repeatedTask(fun func() error, delay time.Duration) {
	// run immediately
	n.Dispatch(fun)
	ticker := time.NewTicker(delay)
	defer ticker.Stop()
	for n.Context.Err() == nil {
		select {
		case <-n.Context.Done():
			return
		case <-ticker.C:
			n.Dispatch(fun)
		}
	}
}

func (n *Nylon) RepeatTask(fun func() error, delay time.Duration) {
	go n.repeatedTask(fun, delay)
}
