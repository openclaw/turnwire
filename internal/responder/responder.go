package responder

import "context"

// Responder is a text-only model boundary. Implementations receive text and
// return text; they do not expose tools, files, URLs, or action requests.
type Responder interface {
	Respond(context.Context, string) (string, error)
}
