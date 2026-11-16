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
	var newID int64
	err := r.Pool.QueryRow(ctx,
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
	rows, err := r.Pool.Query(ctx, `SELECT id, email, pass_hash FROM users WHERE email = $1`, email)

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

func (r *Repository) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "repository.postgres.IsAdmin"
	var isAdmin bool
	err := r.Pool.QueryRow(ctx, `SELECT is_admin FROM users WHERE id = $1`, userID).Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, repository.ErrUserNotFound
		}

		return false, fmt.Errorf("%s:%w", op, err)
	}

	return isAdmin, nil
}

func (r *Repository) App(ctx context.Context, appID int) (models.App, error) {
	const op = "repository.postgres.App"
	rows, err := r.Pool.Query(ctx, `SELECT id, name, secret FROM apps WHERE id = $1`, appID)

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
