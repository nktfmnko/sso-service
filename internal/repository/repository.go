package repository

import "errors"

var (
	ErrUserExists          = errors.New("user already exists")
	ErrTokenExists         = errors.New("token already exists")
	ErrUserNotFound        = errors.New("user not found")
	ErrAppNotFound         = errors.New("app not found")
	ErrSessionNotFound     = errors.New("session not found")
	ErrTokenNotFound       = errors.New("token not found")
	ErrTokenAlreadyRevoked = errors.New("token already revoked")
)
