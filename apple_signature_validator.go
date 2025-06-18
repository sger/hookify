package main

import (
	"crypto/hmac"
	"crypto/sha256"
)

type AppleSignatureValidator struct {
	secret string
}

func NewAppleSignatureValidator(secret string) *AppleSignatureValidator {
	return &AppleSignatureValidator{
		secret: secret,
	}
}

func (s *AppleSignatureValidator) computeSignature(payload []byte) []byte {
	mac := hmac.New(sha256.New, []byte(s.secret))
	mac.Write(payload)
	return mac.Sum(nil)
}

func (s *AppleSignatureValidator) Verify(payload []byte, receivedMAC []byte) bool {
	expectedMAC := s.computeSignature(payload)
	return hmac.Equal(expectedMAC, receivedMAC)
}
