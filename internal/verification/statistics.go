package verification

import (
	"fmt"
	"math"
)

type BayesianTracker struct {
	PriorHonest    float64
	CurrentPHonest float64
	QueryHistory   []QueryResult

	LambdaHonest    float64
	LambdaDishonest float64
}

type QueryResult struct {
	QueryID       int
	Suspicion     float64
	Contradiction bool
	PHonestAfter  float64
}

func NewBayesianTracker(priorHonest float64) *BayesianTracker {
	return &BayesianTracker{
		PriorHonest:     priorHonest,
		CurrentPHonest:  priorHonest,
		QueryHistory:    make([]QueryResult, 0),
		LambdaHonest:    2.0,
		LambdaDishonest: 0.5,
	}
}

func (bt *BayesianTracker) Update(queryID int, suspicion float64, contradiction bool) float64 {
	result := QueryResult{
		QueryID:       queryID,
		Suspicion:     suspicion,
		Contradiction: contradiction,
	}

	if contradiction {
		bt.CurrentPHonest = 0.0
		result.PHonestAfter = 0.0
		bt.QueryHistory = append(bt.QueryHistory, result)
		return bt.CurrentPHonest
	}

	// Likelihood model using exponential distribution
	// P(suspicion | honest) ~ Exp(lambda_honest)
	// P(suspicion | dishonest) ~ Exp(lambda_dishonest)

	pResultIfHonest := bt.LambdaHonest * math.Exp(-bt.LambdaHonest*suspicion)
	pLow := bt.LambdaHonest * math.Exp(-bt.LambdaHonest*suspicion)
	pHigh := bt.LambdaDishonest * math.Exp(-bt.LambdaDishonest*suspicion)
	pResultIfDishonest := 0.5*pLow + 0.5*pHigh
	pResult := pResultIfHonest*bt.CurrentPHonest + pResultIfDishonest*(1-bt.CurrentPHonest)

	if pResult > 0 {
		bt.CurrentPHonest = (pResultIfHonest * bt.CurrentPHonest) / pResult
	}

	result.PHonestAfter = bt.CurrentPHonest
	bt.QueryHistory = append(bt.QueryHistory, result)
	return bt.CurrentPHonest
}

func (bt *BayesianTracker) GetConfidence() float64 {
	return 1 - bt.CurrentPHonest
}

func (bt *BayesianTracker) ShouldContinue(targetConfidence float64, maxQueries int) (bool, string) {
	if len(bt.QueryHistory) >= maxQueries {
		return false, "MAX_QUERIES_REACHED"
	}

	if bt.CurrentPHonest <= 1-targetConfidence {
		return false, "DISHONEST_DETECTED"
	}

	if bt.CurrentPHonest >= targetConfidence {
		return false, "HONEST_CONFIRMED"
	}

	return true, "CONTINUE"
}

func (bt *BayesianTracker) Reset() {
	bt.CurrentPHonest = bt.PriorHonest
	bt.QueryHistory = make([]QueryResult, 0)
}

func (bt *BayesianTracker) Summary() string {
	return fmt.Sprintf("P(honest)=%.4f, Queries=%d, Confidence(dishonest)=%.2f%%",
		bt.CurrentPHonest, len(bt.QueryHistory), bt.GetConfidence()*100)
}

type SPRTTest struct {
	Alpha          float64 // false positive
	Beta           float64 // false negative
	ThetaDishonest float64 // Assumed fraction of affected packets under H1

	A float64 // Upper boundary (reject H0 = honest)
	B float64 // Lower boundary (accept H0)

	LogLR    float64
	NQueries int
	Decision string
}

func NewSPRTTest(alpha, beta, thetaDishonest float64) *SPRTTest {
	return &SPRTTest{
		Alpha:          alpha,
		Beta:           beta,
		ThetaDishonest: thetaDishonest,
		A:              (1 - beta) / alpha,
		B:              beta / (1 - alpha),
		LogLR:          0,
		NQueries:       0,
		Decision:       "",
	}
}

func (s *SPRTTest) Update(involvesSuspiciousPacket bool, observedSuspicious bool) string {
	if !involvesSuspiciousPacket {
		return s.Decision
	}

	p0 := 0.05 // False suspicion rate when honest
	p1 := 0.40 // True positive rate when querying lied packet

	var logLRIncrement float64
	if observedSuspicious {
		logLRIncrement = math.Log(p1 / p0)
	} else {
		logLRIncrement = math.Log((1 - p1) / (1 - p0))
	}

	s.LogLR += logLRIncrement
	s.NQueries++
	lr := math.Exp(s.LogLR)

	if lr >= s.A {
		s.Decision = "REJECT_H0" // SNP is dishonest
	} else if lr <= s.B {
		s.Decision = "ACCEPT_H0" // SNP is honest
	}

	return s.Decision
}

func (s *SPRTTest) Reset() {
	s.LogLR = 0
	s.NQueries = 0
	s.Decision = ""
}

func (s *SPRTTest) Summary() string {
	lr := math.Exp(s.LogLR)
	return fmt.Sprintf("LR=%.4f, Queries=%d, Decision=%s, Boundaries=[%.4f, %.4f]",
		lr, s.NQueries, s.Decision, s.B, s.A)
}

type ProbabilityModel struct {
	NumLiedPackets int
	TotalPackets   int
	PInconsistent  float64
}

func NewProbabilityModel(numLied, total int, pInconsistent float64) *ProbabilityModel {
	return &ProbabilityModel{
		NumLiedPackets: numLied,
		TotalPackets:   total,
		PInconsistent:  pInconsistent,
	}
}

func (pm *ProbabilityModel) ProbSingleQueryCatchesLie() float64 {
	k := float64(pm.NumLiedPackets)
	m := float64(pm.TotalPackets)

	if m <= 1 || k == 0 {
		return 0
	}

	pInvolvesLie := 1 - ((m-k)/m)*((m-k-1)/(m-1))
	return pInvolvesLie * pm.PInconsistent
}

func (pm *ProbabilityModel) ProbDetectAfterNQueries(n int) float64 {
	pSingle := pm.ProbSingleQueryCatchesLie()
	pNotDetect := math.Pow(1-pSingle, float64(n))
	return 1 - pNotDetect
}

func (pm *ProbabilityModel) QueriesNeededForConfidence(confidence float64) int {
	pSingle := pm.ProbSingleQueryCatchesLie()

	if pSingle <= 0 {
		return math.MaxInt32
	}

	// Solve: 1 - (1-p)^n >= confidence
	// n >= log(1-confidence) / log(1-p)
	n := math.Ceil(math.Log(1-confidence) / math.Log(1-pSingle))

	if n < 0 {
		return math.MaxInt32
	}
	return int(n)
}

func (pm *ProbabilityModel) Summary() string {
	pSingle := pm.ProbSingleQueryCatchesLie()
	p90 := pm.ProbDetectAfterNQueries(100)
	n95 := pm.QueriesNeededForConfidence(0.95)

	return fmt.Sprintf("P(catch per query)=%.4f, P(detect after 100)=%.4f, Queries for 95%% conf=%d",
		pSingle, p90, n95)
}

type ConfidenceTracker struct {
	Bayesian  *BayesianTracker
	SPRT      *SPRTTest
	ProbModel *ProbabilityModel

	ContradictionsFound int
	QueriesExecuted     int
}

func NewConfidenceTracker(prior float64, alpha, beta, theta float64, numLied, total int) *ConfidenceTracker {
	return &ConfidenceTracker{
		Bayesian:  NewBayesianTracker(prior),
		SPRT:      NewSPRTTest(alpha, beta, theta),
		ProbModel: NewProbabilityModel(numLied, total, 0.3),
	}
}

func (ct *ConfidenceTracker) ProcessResult(queryID int, suspicion float64, contradiction bool, involvesSuspicious bool) {
	ct.QueriesExecuted++

	if contradiction {
		ct.ContradictionsFound++
	}

	ct.Bayesian.Update(queryID, suspicion, contradiction)
	ct.SPRT.Update(involvesSuspicious, suspicion > 0.3)
}

func (ct *ConfidenceTracker) GetVerdict() (string, float64) {
	if ct.ContradictionsFound > 0 {
		return "DISHONEST_PROVEN", 1.0
	}

	if ct.SPRT.Decision == "REJECT_H0" {
		return "DISHONEST_STATISTICAL", ct.Bayesian.GetConfidence()
	}

	if ct.SPRT.Decision == "ACCEPT_H0" {
		return "HONEST", ct.Bayesian.CurrentPHonest
	}

	if ct.Bayesian.GetConfidence() >= 0.95 {
		return "DISHONEST_LIKELY", ct.Bayesian.GetConfidence()
	}

	if ct.Bayesian.CurrentPHonest >= 0.95 {
		return "HONEST_LIKELY", ct.Bayesian.CurrentPHonest
	}

	return "INCONCLUSIVE", 0.5
}

func (ct *ConfidenceTracker) Summary() string {
	verdict, conf := ct.GetVerdict()
	return fmt.Sprintf("Verdict: %s (confidence=%.2f%%), Queries=%d, Contradictions=%d\n  Bayesian: %s\n  SPRT: %s\n  Model: %s",
		verdict, conf*100, ct.QueriesExecuted, ct.ContradictionsFound,
		ct.Bayesian.Summary(), ct.SPRT.Summary(), ct.ProbModel.Summary())
}
