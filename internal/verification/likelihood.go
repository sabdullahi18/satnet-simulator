package verification

import "math"

// likelihoodTable caches precomputed log-likelihoods for all combinations of
// (contradiction, flagInconsistent) to avoid calling math.Log repeatedly in the hot path.
// Using log-likelihoods prevents numerical underflow when multiplying many small
// probabilities together, and addition is computationally faster and more numerically stable.
type likelihoodTable struct {
	// logLikelihoods[contradiction][flagInconsistent][hypothesis]
	logLikelihoods [2][2][3]float64
}

func newLikelihoodTable(epsilon, eta float64) *likelihoodTable {
	lt := &likelihoodTable{}
	for c := 0; c < 2; c++ {
		for f := 0; f < 2; f++ {
			contradiction := c == 1
			flagInconsistent := f == 1

			var contraProb [3]float64
			if contradiction {
				contraProb = [3]float64{epsilon, eta, 1 - eta}
			} else {
				contraProb = [3]float64{1 - epsilon, 1 - eta, eta}
			}

			var flagProb [3]float64
			if flagInconsistent {
				flagProb = [3]float64{epsilon, 1 - eta, eta}
			} else {
				flagProb = [3]float64{1 - epsilon, eta, 1 - eta}
			}

			for i := range 3 {
				// multiplying before taking the log is equivalent to adding logs but saves a math.Log call.
				lt.logLikelihoods[c][f][i] = math.Log(contraProb[i] * flagProb[i])
			}
		}
	}
	return lt
}

func (lt *likelihoodTable) jointLogLikelihoods(contradiction, flagInconsistent bool) [3]float64 {
	cIdx := 0
	if contradiction {
		cIdx = 1
	}
	fIdx := 0
	if flagInconsistent {
		fIdx = 1
	}
	return lt.logLikelihoods[cIdx][fIdx]
}
