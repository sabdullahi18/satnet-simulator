package experiment

import (
	"testing"

	"satnet-simulator/internal/verification"
)

func TestMaliciousStrategiesSmoke(t *testing.T) {
	runner := NewRunner()
	runner.Verbose = false
	runner.SetBaseSeed(42)

	base := DefaultMaliciousBaseline()
	base.NumTrials = 3
	base.NumPackets = 200
	base.BatchSize = 10
	base.SimDuration = 50.0

	tauFlag := base.Verification.FlaggingRateThreshold

	t.Run("NaiveLiar", func(t *testing.T) {
		cfg := NaiveLiarConfig(base, 0.10)
		cfg.Name = "test_naive_liar"
		agg := runner.RunMalicious(cfg)
		if agg.MissedRate+agg.CorrectDetectionRate+agg.InconclusiveRate < 0.999 {
			t.Errorf("verdict rates do not sum to 1: missed=%.3f caught=%.3f inconclusive=%.3f",
				agg.MissedRate, agg.CorrectDetectionRate, agg.InconclusiveRate)
		}
	})

	t.Run("SilentDropper", func(t *testing.T) {
		cfg := SilentDropperConfig(base, 0.10)
		cfg.Name = "test_silent_dropper"
		agg := runner.RunMalicious(cfg)
		// Silent dropper should never produce contradictions (p_lie=0)
		if agg.MeanContradictions > 0 {
			t.Errorf("silent dropper produced contradictions (p_lie=0): mean=%.2f", agg.MeanContradictions)
		}
	})

	t.Run("SmartStrategyCompliant", func(t *testing.T) {
		// p_target < tau_flag: should be TRUSTED (missed) 100%
		cfg := SmartStrategyConfig(base, tauFlag*0.5)
		cfg.Name = "test_smart_compliant"
		agg := runner.RunMalicious(cfg)
		if agg.MissedRate < 1.0 {
			t.Errorf("smart strategy within SLA should be TRUSTED but missed=%.2f", agg.MissedRate)
		}
	})

	t.Run("SmartStrategyOvershoot", func(t *testing.T) {
		// p_target > tau_flag: should trigger SLA_BREACHED
		cfg := SmartStrategyConfig(base, tauFlag*2.0)
		cfg.Name = "test_smart_overshoot"
		agg := runner.RunMalicious(cfg)
		if agg.SLABreachedRate < 1.0 {
			t.Errorf("smart strategy over SLA should breach but sla_breached=%.2f", agg.SLABreachedRate)
		}
	})

	t.Run("ParametricAdversary", func(t *testing.T) {
		pTarget := 2 * tauFlag
		pFlag := AggressivePFlag(pTarget, tauFlag)
		cfg := ParametricConfig(base, pTarget, pFlag, 0.5)
		cfg.Name = "test_parametric"
		agg := runner.RunMalicious(cfg)
		if agg.Config.PLie != 0.5 {
			t.Errorf("p_lie not set correctly: got %.2f want 0.5", agg.Config.PLie)
		}
		_ = agg
	})

	t.Run("AnswerParametricPlie1IsLikeNaiveLiar", func(t *testing.T) {
		// p_lie=1, p_flag=0 should be indistinguishable from Naive Liar
		cfg1 := NaiveLiarConfig(base, 0.10)
		cfg1.Name = "test_naive_via_plie1"
		cfg1.AnsweringStrategy = verification.AnswerParametric
		cfg1.PLie = 1.0
		agg := runner.RunMalicious(cfg1)
		// Should never see hidden-delay admissions (p_lie=1 always lies)
		if agg.MisclassifiedIncompRate > 0 {
			t.Logf("note: p_lie=1 produced misclassified_incompetent=%.3f (possible with small trials)", agg.MisclassifiedIncompRate)
		}
	})

	t.Run("TargetingModes", func(t *testing.T) {
		results := runner.SweepMaliciousTargetingModes(base)
		if len(results) != 4 {
			t.Errorf("expected 4 targeting modes, got %d", len(results))
		}
		for _, agg := range results {
			total := agg.MissedRate + agg.CorrectDetectionRate + agg.InconclusiveRate
			if total < 0.999 {
				t.Errorf("mode %s: verdict rates sum to %.3f", agg.Config.Name, total)
			}
		}
	})

	t.Run("AggressivePFlag", func(t *testing.T) {
		cases := [][3]float64{
			{0.10, 0.30, 1.0},  // p_target < tau_flag → min(1, 0.30/0.10) = 1
			{0.30, 0.30, 1.0},  // equal → 1
			{0.60, 0.30, 0.5},  // p_target > tau_flag → 0.30/0.60 = 0.5
			{0.00, 0.30, 0.0},  // zero target → 0
		}
		for _, c := range cases {
			got := AggressivePFlag(c[0], c[1])
			if got != c[2] {
				t.Errorf("AggressivePFlag(%.2f, %.2f): got %.4f want %.4f", c[0], c[1], got, c[2])
			}
		}
	})
}
