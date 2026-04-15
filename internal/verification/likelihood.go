package verification

import "math"

type LikelihoodTable struct {
	Epsilon float64
	Eta     float64
}

func DefaultLikelihoodTable() LikelihoodTable {
	return LikelihoodTable{
		Epsilon: 1e-3,
		Eta:     0.05,
	}
}

func (lt LikelihoodTable) contraLikelihoods(contradiction bool) [3]float64 {
	if contradiction {
		return [3]float64{lt.Epsilon, lt.Eta, 1 - lt.Eta}
	}
	return [3]float64{1 - lt.Epsilon, 1 - lt.Eta, lt.Eta}
}

func (lt LikelihoodTable) flagLikelihoods(flagInc bool) [3]float64 {
	if flagInc {
		return [3]float64{lt.Epsilon, 1 - lt.Eta, lt.Eta}
	}
	return [3]float64{1 - lt.Epsilon, lt.Eta, 1 - lt.Eta}
}

func (lt LikelihoodTable) JointLogLikelihoods(contradiction, flagInc bool) [3]float64 {
	c := lt.contraLikelihoods(contradiction)
	f := lt.flagLikelihoods(flagInc)
	var out [3]float64
	for i := 0; i < 3; i++ {
		out[i] = math.Log(c[i]) + math.Log(f[i])
	}
	return out
}
