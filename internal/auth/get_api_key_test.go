package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Valid ApiKey Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret_key_123"},
			},
			expectedKey:   "secret_key_123",
			expectedError: nil,
		},
		{
			name: "Malformed Authorization Header - Wrong Scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer token_123"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Missing Token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			if tt.expectedError != nil {
				if err == nil || err.Error() != tt.expectedError.Error() {
					t.Fatalf("expected error: %v, got: %v", tt.expectedError, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if apiKey != tt.expectedKey {
				t.Errorf("expected apiKey: %s, got: %s", tt.expectedKey, apiKey)
			}
		})
	}
}
