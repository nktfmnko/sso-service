package models

import "time"

type RefreshSession struct {
	ID        int64
	UserID    int64
	AppID     int
	TokenHash string
	ExpiresAt time.Time
}
