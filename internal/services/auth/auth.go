package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sso_service/internal/domain/models"
	"sso_service/internal/lib/jwt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (int64, error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	UserByID(ctx context.Context, userID int64) (models.User, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

type TokenStorage interface {
	SaveRefreshToken(ctx context.Context, session models.RefreshSession) error
	RefreshSession(ctx context.Context, tokenHash string) (models.RefreshSession, error)
	RotateRefreshToken(ctx context.Context, oldSessionID int64, newSession models.RefreshSession) error
}

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrAppNotFound         = errors.New("app not found")
	ErrUserExists          = errors.New("user already exists")
	ErrUserNotFound        = errors.New("user not found")
	ErrTokenNotFound       = errors.New("token not found")
	ErrTokenExists         = errors.New("token already exists")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrTokenAlreadyRevoked = errors.New("token already revoked")
	ErrSessionNotFound     = errors.New("session not found")
)

type Auth struct {
	log             *slog.Logger
	userSaver       UserSaver
	userProvider    UserProvider
	appProvider     AppProvider
	tokenStorage    TokenStorage
	tokenTTL        time.Duration
	refreshTokenTTL time.Duration
}

func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenStorage TokenStorage,
	tokenTTL time.Duration,
	refreshTokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:             log,
		userSaver:       userSaver,
		userProvider:    userProvider,
		appProvider:     appProvider,
		tokenStorage:    tokenStorage,
		tokenTTL:        tokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

func (a *Auth) Login(ctx context.Context, email, password string, appID int) (string, string, error) {
	const op = "auth.Login"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("login user")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		a.log.Warn("failed to get user", err)

		return "", "", fmt.Errorf("%s: %w", op, parseRepositoryError(err))
	}
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", err)

		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, parseRepositoryError(err))
	}

	log.Info("user logged in successfully")
	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", err)

		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	rawRefreshToken, tokenHash, err := generateRefreshToken()
	if err != nil {
		a.log.Error("failed to generate refresh token", err)
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	if err = a.tokenStorage.SaveRefreshToken(ctx, models.RefreshSession{
		UserID:    user.ID,
		AppID:     app.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(a.refreshTokenTTL),
	}); err != nil {
		a.log.Error("failed to save refresh token", err)
		return "", "", fmt.Errorf("%s: %w", op, parseRepositoryError(err))
	}

	return token, rawRefreshToken, nil
}

func (a *Auth) Register(ctx context.Context, email, password string) (int64, error) {
	const op = "auth.Register"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("fail to generate pass hash", err)
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	userID, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		log.Error("fail to save user", err)
		return 0, fmt.Errorf("%s: %w", op, parseRepositoryError(err))
	}

	return userID, nil
}

func (a *Auth) Refresh(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error) {
	const op = "auth.Refresh"
	log := a.log.With(
		slog.String("op", op),
	)

	log.Info("refreshing token")

	tokenHash := hashToken(refreshToken)

	session, err := a.tokenStorage.RefreshSession(ctx, tokenHash)
	if err != nil {
		log.Error("failed to get refresh session", slog.Any("err", err))
		return "", "", fmt.Errorf("%s: %w", op, parseRepositoryError(err))
	}

	if time.Now().After(session.ExpiresAt) {
		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidRefreshToken)
	}

	user, err := a.userProvider.UserByID(ctx, session.UserID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, parseRepositoryError(err))
	}

	app, err := a.appProvider.App(ctx, session.AppID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, parseRepositoryError(err))
	}

	accessToken, err = jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate access token", slog.Any("err", err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	newRefreshToken, newHash, err := generateRefreshToken()
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	err = a.tokenStorage.RotateRefreshToken(ctx, session.ID, models.RefreshSession{
		UserID:    user.ID,
		AppID:     app.ID,
		TokenHash: newHash,
		ExpiresAt: time.Now().Add(a.refreshTokenTTL),
	})
	if err != nil {
		log.Error("failed to rotate refresh token", slog.Any("err", err))
		return "", "", fmt.Errorf("%s: %w", op, parseRepositoryError(err))
	}

	return accessToken, newRefreshToken, nil
}

func (a *Auth) RefreshTokenTTL() time.Duration {
	return a.refreshTokenTTL
}
