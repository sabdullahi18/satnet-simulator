package network

import (
	"math"
	"math/rand"
	"sort"
)

type DelayModelConfig struct {
	BaseDelayMin      float64
	BaseDelayMax      float64
	TransitionRate    float64
	IncompetenceRate  float64
	IncompetenceMu    float64
	IncompetenceSigma float64
	TargetedMin       float64
	TargetedMax       float64
}

type PathTransition struct {
	time      float64
	baseDelay float64
}

type DelayModel struct {
	config      DelayModelConfig
	transitions []PathTransition
	initialised bool
}

type DelayComponents struct {
	BaseDelay         float64
	IncompetenceDelay float64
	TargetedDelay     float64
	TotalDelay        float64
}

func NewDelayModelConfig(cfg DelayModelConfig) *DelayModel {
	return &DelayModel{
		config:      cfg,
		transitions: make([]PathTransition, 0),
		initialised: false,
	}
}

func (dm *DelayModel) Initialise(duration float64) {
	dm.transitions = make([]PathTransition, 0)
	currentTime := 0.0
	dm.transitions = append(dm.transitions, PathTransition{
		time:      0,
		baseDelay: dm.sampleBaseDelay(),
	})

	for currentTime < duration {
		// interArrival = -ln(1-U)/lambda
		interArrival := rand.ExpFloat64() / dm.config.TransitionRate
		currentTime += interArrival

		if currentTime < duration {
			dm.transitions = append(dm.transitions, PathTransition{
				time:      currentTime,
				baseDelay: dm.sampleBaseDelay(),
			})
		}
	}

	dm.initialised = true
}

func (dm *DelayModel) sampleBaseDelay() float64 {
	return dm.config.BaseDelayMin + rand.Float64()*(dm.config.BaseDelayMax-dm.config.BaseDelayMin)
}

func (dm *DelayModel) getBaseDelay(t float64) float64 {
	if !dm.initialised || len(dm.transitions) == 0 {
		return dm.sampleBaseDelay()
	}

	idx := sort.Search(len(dm.transitions), func(i int) bool {
		return dm.transitions[i].time > t
	})

	if idx == 0 {
		return dm.transitions[0].baseDelay
	}
	return dm.transitions[idx-1].baseDelay
}

func (dm *DelayModel) getIncompetenceDelay() float64 {
	// lognormal distribution
	z := rand.NormFloat64()
	return math.Exp(dm.config.IncompetenceMu + dm.config.IncompetenceSigma*z)
}

func (dm *DelayModel) getTargetedDelay() float64 {
	return dm.config.TargetedMin + rand.Float64()*(dm.config.TargetedMax-dm.config.TargetedMin)
}

func (dm *DelayModel) ComputeTotalDelay(sendTime float64, hasIncompetence bool, isTargeted bool) DelayComponents {
	baseDelay := dm.getBaseDelay(sendTime)

	incompetenceDelay := 0.0
	if hasIncompetence {
		incompetenceDelay = dm.getIncompetenceDelay()
	}

	targetedDelay := 0.0
	if isTargeted {
		targetedDelay = dm.getTargetedDelay()
	}

	return DelayComponents{
		BaseDelay:         baseDelay,
		IncompetenceDelay: incompetenceDelay,
		TargetedDelay:     targetedDelay,
		TotalDelay:        baseDelay + incompetenceDelay + targetedDelay,
	}
}
