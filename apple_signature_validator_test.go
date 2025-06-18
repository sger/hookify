package main

import (
	"encoding/hex"
	"testing"
)

func TestNewAppleSignatureValidator(t *testing.T) {
	secret := "test-secret"
	validator := NewAppleSignatureValidator(secret)

	if validator == nil {
		t.Fatal("NewAppleSignatureValidator returned nil")
	}

	payload := []byte("test")
	signature := validator.computeSignature(payload)

	if !validator.Verify(payload, signature) {
		t.Error("Validator should verify its own signature")
	}
}

func TestVerify(t *testing.T) {
	secret := "test-secret-key"
	validator := NewAppleSignatureValidator(secret)

	tests := []struct {
		name         string
		payload      string
		getSignature func() []byte
		shouldVerify bool
	}{
		{
			name:    "valid signature",
			payload: "test payload",
			getSignature: func() []byte {
				return validator.computeSignature([]byte("test payload"))
			},
			shouldVerify: true,
		},
		{
			name:    "invalid signature",
			payload: "test payload",
			getSignature: func() []byte {
				invalid, _ := hex.DecodeString("deadbeefcafebabe1234567890abcdef")
				return invalid
			},
			shouldVerify: false,
		},
		{
			name:    "empty payload with valid signature",
			payload: "",
			getSignature: func() []byte {
				return validator.computeSignature([]byte(""))
			},
			shouldVerify: true,
		},
		{
			name:    "payload mismatch",
			payload: "different payload",
			getSignature: func() []byte {
				return validator.computeSignature([]byte("original payload"))
			},
			shouldVerify: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature := tt.getSignature()
			result := validator.Verify([]byte(tt.payload), signature)

			if result != tt.shouldVerify {
				t.Errorf("Verify() = %v, expected %v", result, tt.shouldVerify)
			}
		})
	}
}

func TestVerifyWithDifferentSecrets(t *testing.T) {
	payload := []byte("test message")

	validator1 := NewAppleSignatureValidator("secret1")
	validator2 := NewAppleSignatureValidator("secret2")

	signature1 := validator1.computeSignature(payload)

	if validator2.Verify(payload, signature1) {
		t.Error("Signature should not verify with different secret")
	}

	if !validator1.Verify(payload, signature1) {
		t.Error("Signature should verify with same secret")
	}
}

func TestSignatureConsistency(t *testing.T) {
	validator := NewAppleSignatureValidator("consistent-secret")
	payload := []byte("consistency test")

	sig1 := validator.computeSignature(payload)
	sig2 := validator.computeSignature(payload)

	if hex.EncodeToString(sig1) != hex.EncodeToString(sig2) {
		t.Error("computeSignature should return consistent results")
	}

	if !validator.Verify(payload, sig1) || !validator.Verify(payload, sig2) {
		t.Error("Both signatures should verify successfully")
	}
}
