package app

import (
	"context"
	"log/slog"
	grpcapp "sso_service/internal/app/grpc"
	"sso_service/internal/config"
	"sso_service/internal/repository/postgres"
	"sso_service/internal/services/auth"
)

type App struct {
	GRPCServer *grpcapp.App
	Repo       *postgres.Repository
}

func New(ctx context.Context, config *config.Config, log *slog.Logger) *App {
	repo, err := postgres.NewPool(config, ctx)
	if err != nil {
		panic(err)
	}
	authService := auth.New(log, repo, repo, repo, repo, config.TokenTTL, config.RefreshTokenTTL)

	grpcApp := grpcapp.NewApp(log, authService, config.GRPC.Port)

	return &App{GRPCServer: grpcApp, Repo: repo}
}
