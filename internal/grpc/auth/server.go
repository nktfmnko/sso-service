package auth

import (
	"context"
	"errors"
	"sso_service/internal/services/auth"
	"time"

	ssov1 "github.com/nktfmnko/sso_protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthService interface {
	Login(ctx context.Context, email, password string, appID int) (token, refreshToken string, err error)
	Register(ctx context.Context, email, password string) (userID int64, err error)
	Refresh(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth AuthService
}

func Register(gRPC *grpc.Server, auth AuthService) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

const (
	emptyValue = 0
)

func (s *serverAPI) Login(ctx context.Context, request *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if err := validateLogin(request); err != nil {
		return nil, err
	}

	token, refreshToken, err := s.auth.Login(ctx, request.GetEmail(), request.GetPassword(), int(request.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid args")
		}
		if errors.Is(err, auth.ErrInvalidAppID) {
			return nil, status.Error(codes.InvalidArgument, "invalid app id")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	if isWebClient(ctx) {
		if err := setResfreshTokenCookie(ctx, refreshToken, 30*24*time.Hour); err != nil {
			return nil, status.Error(codes.Internal, "failed to set cookie")
		}

		return &ssov1.LoginResponse{
			Token: token,
		}, nil
	}

	return &ssov1.LoginResponse{Token: token, RefreshToken: &refreshToken}, nil
}

func (s *serverAPI) Register(ctx context.Context, request *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if err := validateRegister(request); err != nil {
		return nil, err
	}

	userID, err := s.auth.Register(ctx, request.GetEmail(), request.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exist")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterResponse{UserId: userID}, nil
}

func (s *serverAPI) Refresh(ctx context.Context, request *ssov1.RefreshRequest) (*ssov1.RefreshResponse, error) {
	refreshToken, isWeb, err := extractRefreshToken(ctx, request)
	if err != nil {
		return nil, err
	}

	accessToken, newRefreshToken, err := s.auth.Refresh(ctx, refreshToken)
	if err != nil {
		//TODO
		return nil, status.Error(codes.Internal, "internal error")
	}

	if isWeb {
		if err := setResfreshTokenCookie(ctx, newRefreshToken, 30*24*time.Hour); err != nil {
			return &ssov1.RefreshResponse{AccessToken: accessToken}, nil
		}
	}

	return &ssov1.RefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: &newRefreshToken,
	}, nil
}
