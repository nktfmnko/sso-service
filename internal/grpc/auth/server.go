package auth

import (
	"context"

	ssov1 "github.com/nktfmnko/sso_protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthService interface {
	Login(ctx context.Context, email, password string, appID int) (token string, err error)
	Register(ctx context.Context, email, password string) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
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

	token, err := s.auth.Login(ctx, request.GetEmail(), request.GetPassword(), int(request.GetAppId()))
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginResponse{Token: token}, nil
}

func (s *serverAPI) Register(ctx context.Context, request *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if err := validateRegister(request); err != nil {
		return nil, err
	}

	userID, err := s.auth.Register(ctx, request.GetEmail(), request.GetPassword())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.RegisterResponse{UserId: userID}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, request *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if err := validateIsAdmin(request); err != nil {
		return nil, err
	}
	isAdmin, err := s.auth.IsAdmin(ctx, request.GetUserId())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.IsAdminResponse{IsAdmin: isAdmin}, nil
}

func validateLogin(request *ssov1.LoginRequest) error {
	if request.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if request.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	if request.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, "app_id is required")
	}

	return nil
}

func validateRegister(request *ssov1.RegisterRequest) error {
	if request.GetEmail() == "" {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if request.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}

	return nil
}

func validateIsAdmin(request *ssov1.IsAdminRequest) error {
	if request.GetUserId() == emptyValue {
		return status.Error(codes.InvalidArgument, "user_id is required")
	}
	return nil
}
