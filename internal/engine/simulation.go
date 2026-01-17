package engine

import (
	"sort"
)

type Event struct {
	Time   float64
	Action func()
}

type Simulation struct {
	Now    float64
	events []Event
}

func NewSimulation() *Simulation {
	return &Simulation{
		Now:    0.0,
		events: []Event{},
	}
}

func (s *Simulation) Schedule(delay float64, action func()) {
	executionTime := s.Now + delay
	newEvent := Event{
		Time:   executionTime,
		Action: action,
	}

	s.events = append(s.events, newEvent)

	sort.Slice(s.events, func(i, j int) bool {
		return s.events[i].Time < s.events[j].Time
	})
}

func (s *Simulation) ScheduleAt(absoluteTime float64, action func()) {
	if absoluteTime < s.Now {
		return
	}

	newEvent := Event{
		Time:   absoluteTime,
		Action: action,
	}

	s.events = append(s.events, newEvent)

	sort.Slice(s.events, func(i, j int) bool {
		return s.events[i].Time < s.events[j].Time
	})
}

func (s *Simulation) Run(until float64) {
	for len(s.events) > 0 {
		event := s.events[0]

		if event.Time > until {
			break
		}

		s.events = s.events[1:]
		s.Now = event.Time
		event.Action()
	}
}

func (s *Simulation) RunSteps(steps int) {
	for i := 0; i < steps && len(s.events) > 0; i++ {
		event := s.events[0]
		s.events = s.events[1:]
		s.Now = event.Time
		event.Action()
	}
}

func (s *Simulation) PendingEvents() int {
	return len(s.events)
}

func (s *Simulation) NextEventTime() float64 {
	if len(s.events) == 0 {
		return -1
	}
	return s.events[0].Time
}

func (s *Simulation) Clear() {
	s.events = []Event{}
}

func (s *Simulation) Reset() {
	s.Now = 0.0
	s.events = []Event{}
}
