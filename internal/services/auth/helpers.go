package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sso_service/internal/repository"
)

func generateRefreshToken() (raw string, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashToken(raw), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func parseRepositoryError(err error) error {
	switch {
	case errors.Is(err, repository.ErrUserExists):
		return ErrUserExists
	case errors.Is(err, repository.ErrUserNotFound):
		return ErrUserNotFound
	case errors.Is(err, repository.ErrAppNotFound):
		return ErrAppNotFound
	case errors.Is(err, repository.ErrSessionNotFound):
		return ErrSessionNotFound
	case errors.Is(err, repository.ErrTokenNotFound):
		return ErrTokenNotFound
	case errors.Is(err, repository.ErrTokenExists):
		return ErrTokenExists
	case errors.Is(err, repository.ErrTokenAlreadyRevoked):
		return ErrTokenAlreadyRevoked
	default:
		return err
	}
}
