package apiroutes

import (
	"api_example/internal/user"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// Route handler dependencies are function arguments,
// each route handler returns a http.HandleFunc
// We do this so we know what each route's dependencies are
func AddApiRoutes(
	mux *http.ServeMux,
	dbConn *pgx.Conn,
	timeFunc func() time.Time,
) *http.ServeMux {

	mux.HandleFunc(
		"POST /login",
		addMiddleware(
			user.PostLogin(dbConn, timeFunc),
			stdMiddleware,
		),
	)

	mux.HandleFunc(
		"POST /user",
		panicHandler(
			// Not logging request body here, as would would leak user passwords into the logs
			logRequestNoBody(
				user.PostUser(dbConn, timeFunc),
			),
		),
	)

	mux.HandleFunc(
		"GET /user",
		authMiddleware(dbConn, timeFunc)(
			addMiddleware(
				user.GetUser(dbConn),
				stdMiddleware,
			),
		),
	)

	return mux
}
