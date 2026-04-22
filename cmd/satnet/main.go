package main

import (
	"fmt"

	"satnet-simulator/internal/experiment"
)

func main() {
	fmt.Println("================================================================================")
	fmt.Println("     SATNET SIMULATOR - Honest Baseline Evaluation")
	fmt.Println("================================================================================")

	runner := experiment.NewRunner()

	base := experiment.DefaultHonestBaseline()
	base.NumTrials = 200
	base.NumPackets = 2000
	base.BatchSize = 10
	base.SimDuration = 1000.0

	etas := []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.2, 0.3, 0.4}
	etaResults := runner.SweepHonestEta(base, etas)
	if err := runner.SaveAggregates("results/honest/eta_sweep.json", etaResults); err != nil {
		fmt.Printf("warning: could not save η sweep: %v\n", err)
	}

	alphas := []float64{0.8, 0.9, 0.95, 0.99, 0.999, 0.9999}
	alphaResults := runner.SweepHonestAlpha(base, alphas)
	if err := runner.SaveAggregates("results/honest/alpha_sweep.json", alphaResults); err != nil {
		fmt.Printf("warning: could not save α sweep: %v\n", err)
	}

	batches := []int{2, 5, 10, 25, 50, 100}
	batchResults := runner.SweepHonestBatch(base, batches)
	if err := runner.SaveAggregates("results/honest/batch_sweep.json", batchResults); err != nil {
		fmt.Printf("warning: could not save batch sweep: %v\n", err)
	}

	// Trial length: how many packets (and so batches) do we need before the
	// honest verdict resolves? Strict α=0.9999 makes the experiment non-trivial.
	strict := base
	strict.Verification.ConfidenceThreshold = 0.9999
	pkts := []int{20, 50, 100, 200, 500, 1000, 2000}
	pktResults := runner.SweepHonestNumPackets(strict, pkts)
	if err := runner.SaveAggregates("results/honest/numpackets_sweep_strict.json", pktResults); err != nil {
		fmt.Printf("warning: could not save trial-length sweep: %v\n", err)
	}

	lambdas := []float64{0.0, 0.01, 0.05, 0.1, 0.5, 1.0}
	lambdaResults := runner.SweepHonestTransitionRate(base, lambdas)
	if err := runner.SaveAggregates("results/honest/lambda_sweep.json", lambdaResults); err != nil {
		fmt.Printf("warning: could not save λ sweep: %v\n", err)
	}

	epsilons := []float64{1e-5, 1e-4, 1e-3, 1e-2}
	epsResults := runner.SweepHonestEpsilon(base, epsilons)
	if err := runner.SaveAggregates("results/honest/epsilon_sweep.json", epsResults); err != nil {
		fmt.Printf("warning: could not save ε sweep: %v\n", err)
	}

	runner.PrintSummary()
}
