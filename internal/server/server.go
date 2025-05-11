package server

import (
	"api_example/internal/apiroutes"
	"api_example/internal/apiutil"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// StartServer is used in a deployment
//
// For server used in integration tests see: testutil.StartTestServer
func StartServer(dbConn *pgx.Conn) {

	apiAddress, apiPort := apiutil.GetServerAddrPort()

	mux := InitServer(dbConn, time.Now)

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", apiAddress, apiPort),
		Handler: mux,
	}

	if apiAddress == "api" {
		log.Printf("API inside docker: Listening on localhost:%s", apiPort)
	} else {
		log.Printf("Listening on %s:%s", apiAddress, apiPort)
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("unable to start server: %s", err.Error())
	}
}

// InitServer starts router, adds API routes
// Also used inside StartTestServer
func InitServer(
	dbConn *pgx.Conn,
	timeFunc func() time.Time,
) *http.ServeMux {

	mux := http.NewServeMux()
	mux = apiroutes.AddApiRoutes(mux, dbConn, timeFunc)
	return mux
}
