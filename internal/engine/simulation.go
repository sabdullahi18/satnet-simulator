package engine

import (
	"sort"
)

type Event struct {
	Time   float64
	Action func()
}

// Manages the virtual clock and the event schedule
type Simulation struct {
	Now    float64
	events []Event
}

// Initialises a simulation environment
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
