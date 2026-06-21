package verification

import (
	"fmt"
)

type query struct {
	batchID       int
	observedDelay float64
	sentTime      float64
}

func (q query) String() string {
	return fmt.Sprintf("Q(t=%.2f): is_minimal(delay=%.4f)?", q.sentTime, q.observedDelay)
}

type answer struct {
	isMinimal bool
}

func (a answer) String() string {
	if a.isMinimal {
		return "MINIMAL"
	}
	return "NOT_MINIMAL"
}