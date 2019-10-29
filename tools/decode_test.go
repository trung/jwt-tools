package tools

import (
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	_, _, err := DecodeJWT(strings.NewReader("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"), false, false, nil)
	if err != nil {
		t.Error(err)
	}
}
