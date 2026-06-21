package engine

import (
	"container/heap"
)

type Event struct {
	time   float64
	action func()
}

// EventHeap is a min-heap of events prioritised by time.
type EventHeap []Event

func (h EventHeap) Len() int           { return len(h) }
func (h EventHeap) Less(i, j int) bool { return h[i].time < h[j].time }
func (h EventHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *EventHeap) Push(x any) {
	*h = append(*h, x.(Event))
}
func (h *EventHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[0 : n-1]
	return item
}

type Simulation struct {
	Now    float64
	events EventHeap
}

func NewSimulation() *Simulation {
	s := &Simulation{
		Now:    0.0,
		events: make(EventHeap, 0),
	}
	heap.Init(&s.events)
	return s
}

func (s *Simulation) Schedule(delay float64, action func()) {
	executionTime := s.Now + delay
	newEvent := Event{
		time:   executionTime,
		action: action,
	}
	heap.Push(&s.events, newEvent)
}

func (s *Simulation) Run(until float64) {
	for s.events.Len() > 0 {
		if s.events[0].time > until {
			break
		}
		event := heap.Pop(&s.events).(Event)
		s.Now = event.time
		event.action()
	}
}

func (s *Simulation) Clear() {
	s.events = make(EventHeap, 0)
}

func (s *Simulation) Reset() {
	s.Now = 0.0
	s.events = make(EventHeap, 0)
}
