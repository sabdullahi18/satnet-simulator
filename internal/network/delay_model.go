package network

import (
	"math"
	"math/rand"
	"sort"
)

type DelayModel struct {
	BaseDelayMin     float64
	BaseDelayMax     float64
	TransitionRate   float64
	IncompetenceRate float64
	IncompetenceMu   float64
	IncompetenceSigma float64
	DeliberateMin    float64
	DeliberateMax    float64
	transitions      []PathTransition
	initialised      bool
}

type PathTransition struct {
	Time      float64
	BaseDelay float64
}

type DelayComponents struct {
	BaseDelay        float64
	IncompetenceDelay float64
	DeliberateDelay  float64
	TotalDelay       float64
}

func NewDelayModelConfig(cfg DelayModelConfig) *DelayModel {
	return &DelayModel{
		BaseDelayMin:      cfg.BaseDelayMin,
		BaseDelayMax:      cfg.BaseDelayMax,
		TransitionRate:    cfg.TransitionRate,
		IncompetenceRate:  cfg.IncompetenceRate,
		IncompetenceMu:    cfg.IncompetenceMu,
		IncompetenceSigma: cfg.IncompetenceSigma,
		DeliberateMin:     cfg.DeliberateMin,
		DeliberateMax:     cfg.DeliberateMax,
		transitions:       make([]PathTransition, 0),
		initialised:       false,
	}
}

type DelayModelConfig struct {
	BaseDelayMin      float64
	BaseDelayMax      float64
	TransitionRate    float64
	IncompetenceRate  float64
	IncompetenceMu    float64
	IncompetenceSigma float64
	DeliberateMin     float64
	DeliberateMax     float64
}

func (dm *DelayModel) Initialise(duration float64) {
	dm.transitions = make([]PathTransition, 0)

	// Piecewise constant function for base delay
	// Initial segment
	currentTime := 0.0
	dm.transitions = append(dm.transitions, PathTransition{
		Time:      0,
		BaseDelay: dm.sampleBaseDelay(),
	})

	// Generate transitions using Poisson process
	for currentTime < duration {
		// Inter-arrival time for Poisson process is Exponential(lambda)
		interArrival := -math.Log(1.0-rand.Float64()) / dm.TransitionRate
		currentTime += interArrival

		if currentTime < duration {
			dm.transitions = append(dm.transitions, PathTransition{
				Time:      currentTime,
				BaseDelay: dm.sampleBaseDelay(),
			})
		}
	}

	dm.initialised = true
}

func (dm *DelayModel) sampleBaseDelay() float64 {
	return dm.BaseDelayMin + rand.Float64()*(dm.BaseDelayMax-dm.BaseDelayMin)
}

func (dm *DelayModel) GetBaseDelay(t float64) float64 {
	if !dm.initialised || len(dm.transitions) == 0 {
		return dm.sampleBaseDelay()
	}

	// Find the segment that contains t
	idx := sort.Search(len(dm.transitions), func(i int) bool {
		return dm.transitions[i].Time > t
	})

	// transitions[idx] is the first one AFTER t (or len if none)
	// So the active one is idx-1
	if idx == 0 {
		return dm.transitions[0].BaseDelay
	}
	return dm.transitions[idx-1].BaseDelay
}

func (dm *DelayModel) GetIncompetenceDelay() float64 {
	// LogNormal distribution
	z := rand.NormFloat64()
	return math.Exp(dm.IncompetenceMu + dm.IncompetenceSigma*z)
}

func (dm *DelayModel) GetDeliberateDelay() float64 {
	// Uniform distribution for deliberate delay
	return dm.DeliberateMin + rand.Float64()*(dm.DeliberateMax-dm.DeliberateMin)
}

func (dm *DelayModel) ComputeTotalDelay(sendTime float64, hasIncompetence bool, isDeliberate bool) DelayComponents {
	baseDelay := dm.GetBaseDelay(sendTime)

	incompetenceDelay := 0.0
	if hasIncompetence {
		incompetenceDelay = dm.GetIncompetenceDelay()
	}

	deliberateDelay := 0.0
	if isDeliberate {
		deliberateDelay = dm.GetDeliberateDelay()
	}

	return DelayComponents{
		BaseDelay:         baseDelay,
		IncompetenceDelay: incompetenceDelay,
		DeliberateDelay:   deliberateDelay,
		TotalDelay:        baseDelay + incompetenceDelay + deliberateDelay,
	}
}
