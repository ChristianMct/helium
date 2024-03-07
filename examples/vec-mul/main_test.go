package main

import (
	"testing"
)

func TestExtractFirstInteger(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
	}{
		{"abc123def", 123},
		{"xyz456", 456},
		{"789", 789},
		{"1", 1},
		{"a", 0},
		{"-1", 1},
		{"", 0},
	}

	for _, test := range tests {
		result := extractFirstInteger(test.input)
		if result != test.expected {
			t.Errorf("Expected %d, but got %d for input %s", test.expected, result, test.input)
		}
	}
}
