package commerce

import (
	"errors"
	"strings"

	"hyperdns/internal/database"
)

// IsInvalidCredentials lets HTTP handlers collapse unknown users, wrong
// passwords, and suspended accounts into the same public authentication error.
func IsInvalidCredentials(err error) bool {
	return errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrSessionInvalid)
}

// IsRegistrationConflict reports the only expected uniqueness conflict.
func IsRegistrationConflict(err error) bool {
	return errors.Is(err, database.ErrCommerceEmailExists)
}

// NormalizeEmailInput trims user-entered whitespace; canonical validation and
// case-folding remain in the repository so all callers use one rule.
func NormalizeEmailInput(email string) string {
	return strings.TrimSpace(email)
}
