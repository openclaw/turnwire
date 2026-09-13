package mailbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/openclaw/turnwire/internal/approval"
	"github.com/openclaw/turnwire/internal/audit"
	"github.com/openclaw/turnwire/internal/guard"
)

func (s *Service) evaluate(ctx context.Context, messageID, requestID, conversationID, direction, source, destination, text string) (string, string, guard.Evaluation, audit.Entry, error) {
	findings := guard.Scan(text)
	deterministicDecision, deterministicReason := guard.DecisionAllow, "allowed"
	for _, finding := range findings {
		if finding.Decision == guard.DecisionDeny || deterministicDecision == guard.DecisionAllow {
			deterministicDecision, deterministicReason = finding.Decision, finding.Code
		}
	}
	details := messageDetails(direction, source, destination, messageID)
	details["decision"] = deterministicDecision
	details["reason_code"] = deterministicReason
	entry, err := s.appendEvent(messageID, requestID, conversationID, eventDeterministicGuard, "completed", "", "", details)
	if err != nil {
		return "", "", guard.Evaluation{}, audit.Entry{}, err
	}
	if deterministicDecision == guard.DecisionDeny {
		return deterministicDecision, deterministicReason, guard.Evaluation{Model: "not_called"}, entry, nil
	}
	if err := takeBudget(s.guardBudget, s.now()); err != nil {
		failed, appendErr := s.appendEvent(messageID, requestID, conversationID, eventGuardFailed, "failed", "guard_budget_exhausted", "", messageDetails(direction, source, destination, messageID))
		if appendErr != nil {
			return "", "", guard.Evaluation{}, audit.Entry{}, errors.Join(err, appendErr)
		}
		return "", "", guard.Evaluation{}, failed, err
	}
	callCtx, cancel := context.WithTimeout(ctx, s.timeout)
	stopShutdownCancel := context.AfterFunc(s.lifecycleCtx, cancel)
	evaluation, evalErr := s.guard.Evaluate(callCtx, guard.Input{Direction: direction, Source: source, Destination: destination, Text: text, Policy: s.policy})
	callErr := callCtx.Err()
	stopShutdownCancel()
	cancel()
	if callErr != nil {
		evalErr = callErr
	}
	if evalErr != nil {
		failed, appendErr := s.appendEvent(messageID, requestID, conversationID, eventGuardFailed, "failed", guardErrorCode(evalErr), "", messageDetails(direction, source, destination, messageID))
		if appendErr != nil {
			return "", "", guard.Evaluation{}, audit.Entry{}, errors.Join(evalErr, appendErr)
		}
		return "", "", guard.Evaluation{}, failed, fmt.Errorf("model guard failed closed: %w", evalErr)
	}
	details = messageDetails(direction, source, destination, messageID)
	details["decision"] = evaluation.Decision
	details["reason_code"] = evaluation.ReasonCode
	details["model"] = evaluation.Model
	details["policy_version"] = s.policyVersion
	if evaluation.ProviderRequestID != "" {
		details["provider_request_id"] = evaluation.ProviderRequestID
	}
	if evaluation.ResponseID != "" {
		details["provider_response_id"] = evaluation.ResponseID
	}
	entry, err = s.appendEvent(messageID, requestID, conversationID, eventModelGuard, "completed", "", "", details)
	if err != nil {
		return "", "", guard.Evaluation{}, audit.Entry{}, err
	}
	decision, reason := effectiveDecision(deterministicDecision, deterministicReason, evaluation.Decision, evaluation.ReasonCode)
	return decision, reason, evaluation, entry, nil
}

func (s *Service) savePending(messageID, direction, source, destination, text, reason, createdAt string) error {
	return s.approvals.SavePending(approval.Pending{MessageID: messageID, Direction: direction, Source: source, Destination: destination, Body: text, BodySHA256: hashText(text), ReasonCode: reason, CreatedAt: createdAt})
}

func messageDetails(direction, source, destination, messageID string) map[string]string {
	return map[string]string{"direction": direction, "source": source, "destination": destination, "message_id": messageID}
}
func guardErrorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, guard.ErrMissingAPIKey) {
		return "missing_api_key"
	}
	return "provider_error"
}

func effectiveDecision(deterministicDecision, deterministicReason, modelDecision, modelReason string) (string, string) {
	if deterministicDecision == guard.DecisionReview && modelDecision == guard.DecisionAllow {
		return guard.DecisionReview, deterministicReason
	}
	return modelDecision, modelReason
}
