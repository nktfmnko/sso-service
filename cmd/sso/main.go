package main

import (
	"log/slog"
	"os"
	"os/signal"
	"sso_service/internal/app"
	"sso_service/internal/config"
	"syscall"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)
	log.Info("start app", slog.String("env", cfg.Env))

	application := app.New(log, cfg.GRPC.Port, cfg.TokenTTL)

	go application.GRPCServer.MustRun()

	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop

	application.GRPCServer.Stop()
	log.Info("app stopped")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)

	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)

	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}
