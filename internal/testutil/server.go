package testutil

import (
	"api_example/internal/server"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// StartTestServer the server used in tests
func StartTestServer(
	t *testing.T,
	dbConn *pgx.Conn,
	timeFunc func() time.Time,
) *httptest.Server {

	mux := server.InitServer(dbConn, timeFunc)
	testServer := httptest.NewServer(mux)

	t.Cleanup(
		func() {
			testServer.Close()
		},
	)

	return testServer
}
