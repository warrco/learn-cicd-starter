package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	type tc struct {
		name    string
		h       http.Header
		wantKey string
		wantErr error
	}

	newHeader := func(v string) http.Header {
		h := make(http.Header)
		if v != "" {
			h.Set("Authorization", v)
		}
		return h
	}

	tests := []tc{
		{
			name:    "ok_basic",
			h:       newHeader("ApiKey abc123"),
			wantKey: "abc123",
		},
		{
			name:    "missing_header",
			h:       newHeader(""),
			wantErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name:    "leading_spaces_before_scheme",
			h:       newHeader("   ApiKey abc"),
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "no_token_after_scheme",
			h:       newHeader("ApiKey"),
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "wrong_scheme",
			h:       newHeader("Bearer xxxxxxx"),
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := auth.GetAPIKey(tt.h)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErr.Error())
				}
				if err.Error() != tt.wantErr.Error() {
					t.Fatalf("expected error %q, got %q", tt.wantErr.Error(), err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantKey {
				t.Fatalf("want %q, got %q", tt.wantKey, got)
			}
		})
	}
}
