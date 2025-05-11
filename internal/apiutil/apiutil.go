package apiutil

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
)

var FailedToGetUserIDFromCtx = errors.New("failed to retrieve userID from the request ctx")

// UserIDCtxKey is the context key used to retrieve userID from request context
var UserIDCtxKey struct{}

// GetUserIDFromReq gets userID which was saved into the request context with
func GetUserIDFromReq(r *http.Request) (int, error) {

	userIDAny := r.Context().Value(UserIDCtxKey)
	userID, ok := userIDAny.(int)
	if !ok {
		// Not leaking internal error details to the client
		log.Printf("failed to retrieve userID from the request ctx, did you forget to use the authMiddleware middleware?")
		return 0, FailedToGetUserIDFromCtx
	}
	return userID, nil
}

// GetServerAddrPort get the server's address and port
func GetServerAddrPort() (string, string) {

	apiPort := os.Getenv("API_PORT")
	if apiPort == "" {
		apiPort = "8080"
		// TODO: add env var to trigger this fatal error in prod so we can easily debug deployment
		// log.Fatalf("API_PORT is undefined")
	}
	apiAddress := os.Getenv("API_ADDR")
	if apiAddress == "" {
		apiAddress = "localhost"
		// TODO: add env var to trigger this fatal error in prod so we can easily debug deployment
		// log.Fatalf("API_ADDR is undefined")
	}

	return apiAddress, apiPort
}

// GetServerAddrPortForCookie get the server's address and port for cookie
func GetServerAddrPortForCookie() string {

	apiAddress, apiPort := GetServerAddrPort()
	if apiAddress == "localhost" {
		return apiAddress
	}
	return fmt.Sprintf("%s:%s", apiAddress, apiPort)
}
