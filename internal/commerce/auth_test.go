package commerce

import (
	"errors"
	"testing"
)

func TestInvalidCredentialsClassification(t *testing.T) {
	if !IsInvalidCredentials(ErrInvalidCredentials) {
		t.Fatal("invalid credentials sentinel was not classified")
	}
	if !IsInvalidCredentials(ErrSessionInvalid) {
		t.Fatal("invalid session sentinel was not classified")
	}
	if IsInvalidCredentials(errors.New("storage unavailable")) {
		t.Fatal("internal error was classified as invalid credentials")
	}
}
