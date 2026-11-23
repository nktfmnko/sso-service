package postgres

import (
	"context"
	"errors"
	"fmt"
	"sso_service/internal/config"
	"sso_service/internal/domain/models"
	"sso_service/internal/repository"
	"time"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	*pgxpool.Pool
	opTimeout time.Duration
}

func NewPool(config *config.Config, ctx context.Context) (*Repository, error) {
	const op = "repository.postgres.NewPool"
	connectionString := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		config.Postgres.User,
		config.Postgres.Password,
		config.Postgres.Host,
		config.Postgres.Port,
		config.Postgres.Database,
	)
	pgxconfig, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, fmt.Errorf("parse pgxconfig %s: %w", op, err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, pgxconfig)
	if err != nil {
		return nil, fmt.Errorf("create pgx pool: %s: %w", op, err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("pgx pool ping: %s: %w", op, err)
	}

	return &Repository{
		Pool:      pool,
		opTimeout: config.Postgres.OpTimeout,
	}, nil
}

func (r *Repository) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "repository.postgres.SaveUser"
	opCtx, cancel := context.WithTimeout(ctx, r.opTimeout)
	defer cancel()

	var newID int64
	err := r.Pool.QueryRow(opCtx,
		`INSERT INTO users (email, pass_hash) VALUES ($1, $2) RETURNING id`,
		email, passHash).Scan(&newID)

	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return 0, fmt.Errorf("%s:%w", op, repository.ErrUserExists)
		}
		return 0, fmt.Errorf("%s:%w", op, err)
	}

	return newID, nil
}

func (r *Repository) User(ctx context.Context, email string) (models.User, error) {
	const op = "repository.postgres.User"
	opCtx, cancel := context.WithTimeout(ctx, r.opTimeout)
	defer cancel()

	rows, err := r.Pool.Query(opCtx, `SELECT id, email, pass_hash, is_admin FROM users WHERE email = $1`, email)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s:%w", op, repository.ErrUserNotFound)
		}
	}
	user, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.User])
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (r *Repository) UserByID(ctx context.Context, userID int64) (models.User, error) {
	const op = "repository.postgres.UserByID"
	opCtx, cancel := context.WithTimeout(ctx, r.opTimeout)
	defer cancel()

	rows, err := r.Pool.Query(opCtx, `SELECT id, email, pass_hash, is_admin FROM users WHERE id = $1`, userID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s:%w", op, repository.ErrUserNotFound)
		}
	}
	user, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.User])
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (r *Repository) App(ctx context.Context, appID int) (models.App, error) {
	const op = "repository.postgres.App"

	opCtx, cancel := context.WithTimeout(ctx, r.opTimeout)
	defer cancel()

	rows, err := r.Pool.Query(opCtx, `SELECT id, name, secret FROM apps WHERE id = $1`, appID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s:%w", op, repository.ErrAppNotFound)
		}
	}
	app, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.App])
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}

func (r *Repository) SaveRefreshToken(ctx context.Context, session models.RefreshSession) error {
	const op = "repository.postgres.SaveRefreshToken"
	opCtx, cancel := context.WithTimeout(ctx, r.opTimeout)
	defer cancel()

	_, err := r.Pool.Exec(opCtx, `INSERT INTO sessions (user_id, app_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`, session.UserID, session.AppID, session.TokenHash, session.ExpiresAt)
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == pgerrcode.UniqueViolation {
			return fmt.Errorf("user already exists: %w", repository.ErrTokenExists)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (r *Repository) RefreshSession(ctx context.Context, tokenHash string) (models.RefreshSession, error) {
	const op = "repository.postgres.RefreshSession"

	opCtx, cancel := context.WithTimeout(ctx, r.opTimeout)
	defer cancel()

	rows, err := r.Pool.Query(opCtx, `SELECT id, user_id, app_id, token_hash, expires_at, revoked_at FROM sessions WHERE token_hash = $1`, tokenHash)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.RefreshSession{}, fmt.Errorf("%s:%w", op, repository.ErrSessionNotFound)
		}
	}
	session, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.RefreshSession])
	if err != nil {
		return models.RefreshSession{}, fmt.Errorf("%s: %w", op, err)
	}

	return session, nil
}

func (r *Repository) RotateRefreshToken(ctx context.Context, oldSessionID int64, newSession models.RefreshSession) error {
	const op = "repository.postgres.RefreshSession"

	opCtx, cancel := context.WithTimeout(ctx, r.opTimeout)
	defer cancel()

	tx, err := r.Pool.Begin(opCtx)
	if err != nil {
		return fmt.Errorf("%s: begin tx: %w", op, err)
	}
	defer tx.Rollback(opCtx)

	res, err := tx.Exec(opCtx, `UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`, oldSessionID)
	if err != nil {
		return fmt.Errorf("%s: revoke old token: %w", op, err)
	}

	if res.RowsAffected() == 0 {
		return fmt.Errorf("%s: %w", op, repository.ErrTokenAlreadyRevoked)
	}

	_, err = tx.Exec(opCtx,
		`INSERT INTO sessions (user_id, app_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)`,
		newSession.UserID, newSession.AppID, newSession.TokenHash, newSession.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("%s: insert new token: %w", op, err)
	}
	if err := tx.Commit(opCtx); err != nil {
		return fmt.Errorf("%s: commit tx: %w", op, err)
	}

	return nil
}
