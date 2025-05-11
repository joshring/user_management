package apiroutes

import (
	"api_example/internal/apiutil"
	"api_example/internal/database"
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5"
)

// stdMiddleware is middleware you always need
var stdMiddleware = []func(http.HandlerFunc) http.HandlerFunc{
	panicHandler,
	logRequest,
}

// addMiddleware Wrap a function in a slice of middleware functions
func addMiddleware(
	handler http.HandlerFunc,
	middlewareSlice []func(http.HandlerFunc) http.HandlerFunc,
) http.HandlerFunc {

	for _, middleware := range middlewareSlice {
		handler = middleware(handler)
	}
	return handler
}

// authMiddleware handles authorisation checks the sessionPublicID and csrf_token are valid
// those are given to the client after POST /login
//
// dependency inject dbConn and timeFunc, then return regular middleware function
func authMiddleware(
	dbConn *pgx.Conn,
	timeFunc func() time.Time,
) func(next http.HandlerFunc) http.HandlerFunc {

	// Return regular middleware function
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			//=====================================
			// Get csrfToken from csrf_token header

			csrfToken := r.Header.Get("csrf_token")
			if csrfToken == "" {
				log.Printf("no csrf_token header provided\n")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			//=====================================
			// Get session cookie if present, else unauthorized

			if len(r.Cookies()) == 0 {
				log.Printf("no cookies provided, expected \"session\" cookie\n")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			cookie := &http.Cookie{}

			for _, cookieItem := range r.Cookies() {
				if cookieItem.Name == "session" {
					cookie = cookieItem
				}
			}
			if cookie == nil {
				log.Printf("expected \"session\" cookie not found\n")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			sessionPublicID := cookie.Value

			//=====================================
			// Find userID matching sessionPublicID and csrf_token where the session not expired

			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			defer cancel()

			var userID int

			err := database.StartTransaction(dbConn, ctx, func(tx pgx.Tx) error {

				row := tx.QueryRow(
					ctx,
					`select
						"user"."id"
					from "session"
					join "user" on "user"."id" = "session"."user_id"
					where
						"session"."expires_at" >= $1
						and "session"."csrf_token" = $2
						and "session"."public_id" = $3;
				`,
					timeFunc(),
					csrfToken,
					sessionPublicID,
				)

				err := row.Scan(
					&userID,
				)
				if err != nil {
					return err
				}

				return nil
			})
			if err != nil {
				log.Printf("error in authMiddleware: %s\n", err.Error())
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			//=====================================
			// Add requesting user's userID into the request context
			// This can be used by API endpoints and other middleware etc
			r = r.WithContext(
				context.WithValue(
					r.Context(),
					apiutil.UserIDCtxKey,
					userID,
				),
			)

			next(w, r)
		}
	}
}

// logRequest logs the request method, URI and body, then restores the body (if provided)
//
// Used where no sensitive information is contained in the request body, for that use: logRequestNoBody
func logRequest(next http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		defer r.Body.Close()
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("logRequest err: %s\n", err.Error())
			return
		}

		if len(bodyBytes) > 0 {
			// Replace the body back into the request so it can be opened in the handler
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			log.Printf("%s %s body:\n%s\n", r.Method, r.URL, string(bodyBytes))
		} else {
			log.Printf("%s %s\n", r.Method, r.URL)
		}
		next(w, r)
	}
}

// logRequestNoBody logs the request method, URI
//
// Used with sensitive information in the request body, and we do not wish that to go into the logs
func logRequestNoBody(next http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		log.Printf("%s %s\n", r.Method, r.URL)
		next(w, r)
	}
}

// panicHandler recover from panic to avoid an API crash, log stacktrace and return 500
func panicHandler(next http.HandlerFunc) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		defer func() {

			recErr := recover()
			if recErr != nil {
				log.Printf("panic error: %v stack: %v\n", recErr, runtime.StartTrace())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
		}()

		next(w, r)

	}
}
