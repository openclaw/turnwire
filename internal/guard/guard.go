// Package guard implements deterministic and model-based message policy checks.
package guard

import "context"

const (
	DecisionAllow  = "allow"
	DecisionReview = "review"
	DecisionDeny   = "deny"
)

// Input is one direction-specific message policy evaluation.
type Input struct {
	Direction   string `json:"direction"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Text        string `json:"text"`
	Policy      string `json:"policy"`
}

// Verdict is a bounded policy classification. Explanation must not quote text.
type Verdict struct {
	Decision    string   `json:"decision"`
	ReasonCode  string   `json:"reason_code"`
	DataClasses []string `json:"data_classes"`
	Explanation string   `json:"explanation"`
}

// Evaluation adds provider evidence to a model verdict.
type Evaluation struct {
	Verdict
	Model             string
	ProviderRequestID string
	ResponseID        string
}

// Evaluator checks one message. Errors must fail the caller closed.
type Evaluator interface {
	Evaluate(context.Context, Input) (Evaluation, error)
}
