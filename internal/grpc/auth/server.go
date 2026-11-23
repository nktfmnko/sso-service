package auth

import (
	"context"
	"time"

	ssov1 "github.com/nktfmnko/sso_protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type AuthService interface {
	Login(ctx context.Context, email, password string, appID int) (token, refreshToken string, err error)
	Register(ctx context.Context, email, password string) (userID int64, err error)
	Refresh(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, err error)
	RefreshTokenTTL() time.Duration
	Logout(ctx context.Context, refreshToken string, revokeAll bool) error
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
		return nil, ErrorResponse(err, "failed to  login user")
	}

	if isWebClient(ctx) {
		if err := setResfreshTokenCookie(ctx, refreshToken, s.auth.RefreshTokenTTL()); err != nil {
			return nil, ErrorResponse(err, "failed to  set refresh token cookie")
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
		return nil, ErrorResponse(err, "failed to register user")
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
		return nil, ErrorResponse(err, "failed to refres token")
	}

	if isWeb {
		if err := setResfreshTokenCookie(ctx, newRefreshToken, s.auth.RefreshTokenTTL()); err != nil {
			return &ssov1.RefreshResponse{AccessToken: accessToken}, nil
		}
	}

	return &ssov1.RefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: &newRefreshToken,
	}, nil
}

func (s *serverAPI) Logout(ctx context.Context, request *ssov1.LogoutRequest) (*emptypb.Empty, error) {
	refreshToken, isWeb, err := extractRefreshToken(ctx, request)
	if err != nil {
		if isWebClient(ctx) {
			_ = clearRefreshTokenCookie(ctx)
		}
		return nil, err
	}

	if err := s.auth.Logout(ctx, refreshToken, request.GetRevokeAll()); err != nil {
		if isWeb {
			_ = clearRefreshTokenCookie(ctx)
		}
		return nil, ErrorResponse(err, "failed to logout")
	}

	if isWeb {
		if err := clearRefreshTokenCookie(ctx); err != nil {
			return nil, ErrorResponse(err, "failed to clear cookie")
		}
	}

	return nil, nil
}
