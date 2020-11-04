package demoerr

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var ErrNotAuthorized = status.Error(codes.PermissionDenied, "not authorized")
