package app

import (
	"log/slog"
	grpcapp "sso_service/internal/app/grpc"
	"time"
)

type App struct {
	GRPCServer *grpcapp.App
}

func New(log *slog.Logger, grpcPort int, tokenTTL time.Duration) *App {
	// init postgres

	// init auth service

	grpcApp := grpcapp.NewApp(log, grpcPort)

	return &App{GRPCServer: grpcApp}
}
