package auth

import (
	"context"
	"errors"
	"net/http"
	"sso_service/internal/services/auth"
	"strings"
	"time"

	ssov1 "github.com/nktfmnko/sso_protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func setResfreshTokenCookie(ctx context.Context, token string, ttl time.Duration) error {
	cookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		Path:     ssov1.Auth_Refresh_FullMethodName,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	}

	md := metadata.Pairs("set-cookie", cookie.String())
	return grpc.SetHeader(ctx, md)
}

func extractRefreshToken(ctx context.Context, request *ssov1.RefreshRequest) (string, bool, error) {
	if token := request.GetRefreshToken(); token != "" {
		return token, false, nil
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false, status.Error(codes.Unauthenticated, "refresh token is missing")
	}

	var refreshToken string
	for _, rawCookie := range md.Get("cookie") {
		cookies, err := http.ParseCookie(rawCookie)
		if err != nil {
			continue
		}
		for _, c := range cookies {
			if c.Name == "refresh_token" && c.Value != "" {
				refreshToken = c.Value
				break
			}
		}
		if refreshToken != "" {
			break
		}
	}

	if refreshToken == "" {
		return "", false, status.Error(codes.Unauthenticated, "refresh token cookie is missing")
	}

	return refreshToken, true, nil
}

func isWebClient(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}

	if len(md.Get("origin")) > 0 {
		return true
	}

	for _, ct := range md.Get("content-type") {
		if strings.HasPrefix(ct, "application/grpc-web") || strings.HasPrefix(ct, "application/json") {
			return true
		}
	}

	return false
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
func ErrorResponse(err error, msg string) error {
	var code codes.Code
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrInvalidRefreshToken):
		code = codes.InvalidArgument
	case errors.Is(err, auth.ErrUserExists), errors.Is(err, auth.ErrTokenExists):
		code = codes.AlreadyExists
	case errors.Is(err, auth.ErrUserNotFound), errors.Is(err, auth.ErrTokenNotFound), errors.Is(err, auth.ErrSessionNotFound), errors.Is(err, auth.ErrAppNotFound):
		code = codes.NotFound
	case errors.Is(err, auth.ErrTokenAlreadyRevoked):
		code = codes.Unauthenticated
	default:
		code = codes.Internal
	}
	return errorResponse(code, err, msg)
}

func errorResponse(statusCode codes.Code, err error, msg string) error {
	return status.Errorf(statusCode, "%s :%v", msg, err)
}
