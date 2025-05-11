package user

import (
	"api_example/internal/apiutil"
	"api_example/internal/database"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"runtime"
	"strings"
	"time"

	"net/mail"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

//===============================================

type PostUserBody struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type PostUserResp struct {
	PublicID uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Name     string    `json:"name"`
}

// UnmarshalPostUserBody Validate the input body
func UnmarshalPostUserBody(r *http.Request) (PostUserBody, error) {

	bodyBytes, err := io.ReadAll(r.Body)
	defer r.Body.Close()

	var newUser PostUserBody

	err = json.Unmarshal(bodyBytes, &newUser)
	if err != nil {
		return PostUserBody{}, err
	}

	if len(newUser.Name) == 0 {
		return PostUserBody{}, fmt.Errorf("name not provided")
	}

	_, err = mail.ParseAddress(newUser.Email)
	if err != nil {
		return PostUserBody{}, err
	}

	if len(newUser.Password) < 12 {
		return PostUserBody{}, fmt.Errorf("password must 12 or more characters long")
	}

	if newUser.Password == strings.ToLower(newUser.Password) {
		return PostUserBody{}, fmt.Errorf("password must have an upper case letter")
	}

	return newUser, nil
}

// PostUserAdd handles POST /user
//
// Dependency inject dbConn and timeFunc
func PostUser(
	dbConn *pgx.Conn,
	timeFunc func() time.Time,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// Prevent timing attacks (to find if a user already exists) using a random sleep
		defer func() {
			time.Sleep(time.Duration(rand.IntN(500)) * time.Millisecond)
		}()

		newUser, err := UnmarshalPostUserBody(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"error": "%s"}`, err.Error())
			return
		}

		// Side channel attack proof password hashing
		passwordHashed, err := argon2id.CreateHash(
			newUser.Password,
			&argon2id.Params{
				Memory:     128 * 1024,
				Iterations: 4,
				Parallelism: func() uint8 {
					nCPU := runtime.NumCPU()
					if nCPU > 4 {
						return uint8(runtime.NumCPU() / 4)
					} else {
						return 1
					}
				}(),
				SaltLength: 16,
				KeyLength:  64,
			},
		)
		if err != nil {
			// Not leaking internal error details to the client
			log.Printf("internal server error: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// This query must complete within 10 seconds otherwise it will timeout
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		userPublicID := uuid.New()

		err = database.StartTransaction(dbConn, ctx, func(tx pgx.Tx) error {

			//================================
			// Check if the user already exists
			row := tx.QueryRow(
				ctx,
				`select
					"user"."name",
					"user"."email"
				from "user"
				where
					"user"."name" = $1
					and "user"."email" = $2;
				`,
				newUser.Name,
				newUser.Email,
			)

			var userName string
			var userEmail string

			err = row.Scan(
				&userName,
				&userEmail,
			)
			if err != nil {
				// Adding new users so we expect pgx.ErrNoRows here, only show other errors
				if !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
			}

			// User already exists, nothing to do
			// Return http.StatusOK here because we do not want to leak who is and is not a user of the system already
			if err == nil {
				if userEmail != "" && userName != "" {
					log.Printf("attempted to insert duplicate user")
					return nil
				}
			}
			//================================

			res, err := tx.Exec(
				ctx,
				`insert into "user"(
					"public_id", 
					"name", 
					"email",
					"password_hashed",
					"created_at"
				)
				values($1, $2, $3, $4, $5);
				`,
				userPublicID,
				newUser.Name,
				newUser.Email,
				passwordHashed,
				timeFunc(),
			)
			if err != nil {
				return err
			}

			if res.RowsAffected() != 1 {
				return fmt.Errorf("inserting user failed")
			}

			return nil
		})
		if err != nil {
			// Not leaking internal error details to the client
			log.Printf("internal server error: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		response := PostUserResp{
			PublicID: userPublicID,
			Email:    newUser.Email,
			Name:     newUser.Name,
		}

		jsonResponse, err := json.MarshalIndent(response, "", "    ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf(`{"error": "%s"}`, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResponse)
	}
}

//===============================================

var PasswordNotMatchingHash = errors.New("password not matching hash")

type PostLoginResponse struct {
	CSRFToken string `json:"csrf_token"`
}

// PostLogin handles POST /login
//
// Dependency inject dbConn and timeFunc
func PostLogin(
	dbConn *pgx.Conn,
	timeFunc func() time.Time,
) http.HandlerFunc {

	apiAddress, _ := apiutil.GetServerAddrPort()

	return func(w http.ResponseWriter, r *http.Request) {

		// Prevent timing attacks (to find if a user already exists) using a random sleep
		defer func() {
			time.Sleep(time.Duration(rand.IntN(500)) * time.Millisecond)
		}()

		userEmail, password, ok := r.BasicAuth()
		if !ok {
			http.Error(w, `{"error": "email or password is incorrect"}`, http.StatusUnauthorized)
		}

		// This query must complete within 10 seconds otherwise it will timeout
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		var passwordHashed string
		sessionPublicID := uuid.New()
		csrfToken := uuid.New()

		sessionDuration := time.Minute * 60 * 24
		sessionExpirationTime := timeFunc().Add(sessionDuration)
		var userID int
		var numLoginAttempts int

		err := database.StartTransaction(dbConn, ctx, func(tx pgx.Tx) error {

			//================================
			// Check if the user exists
			row := tx.QueryRow(
				ctx,
				`select
					"user"."id",
					"user"."password_hashed",
					"user"."num_login_attempts"
				from "user"
				where
				 	"user"."email" = $1
					and "user"."num_login_attempts" < 10;
				`,
				userEmail,
			)

			err := row.Scan(
				&userID,
				&passwordHashed,
				&numLoginAttempts,
			)
			if err != nil {
				// if user is missing or session is invalid, will return pgx.ErrNoRows
				return err
			}

			// Constant time password hash comparison, mitigates against timing attacks
			ok, err = argon2id.ComparePasswordAndHash(password, passwordHashed)
			if !ok || err != nil {
				return PasswordNotMatchingHash
			}

			//================================
			// Add session

			res, err := tx.Exec(
				ctx,
				`insert into "session"(
					"public_id",
					"csrf_token",
					"user_id",
					"created_at",
					"expires_at"
				)
				values ($1, $2, $3, $4, $5)
				`,
				sessionPublicID,
				csrfToken,
				userID,
				timeFunc(),
				sessionExpirationTime,
			)
			if err != nil {
				return err
			}

			if res.RowsAffected() != 1 {
				return fmt.Errorf("updating user failed")
			}

			// Reset user.num_login_attempts but only if have some failed attempts
			if numLoginAttempts > 0 {

				res, err := dbConn.Exec(
					ctx,
					`update "user" 
						set "num_login_attempts" = 0
					where 
						"user"."id" = $1
					`,
					userID,
				)
				if err != nil {
					return err
				}

				if res.RowsAffected() != 1 {
					return errors.New("unable to update user")
				}

			}

			return nil

		})
		if err != nil {
			// User not found or incorrect password
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, `{"error": "email or password is incorrect"}`, http.StatusUnauthorized)
				return
			}

			if errors.Is(err, PasswordNotMatchingHash) {

				//================================
				// User's login failed! Now increment login attempts
				// user cannot login once num_login_attempts reaches 10
				// We do this outside the original transaction so avoid rolling back the update

				res, err := dbConn.Exec(
					ctx,
					`update "user" 
						set "num_login_attempts" = "num_login_attempts" + 1
					where 
						"user"."id" = $1
					`,
					userID,
				)
				if err != nil {
					// Not leaking internal error details to the client
					log.Printf("unable to update user\n")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				if res.RowsAffected() != 1 {
					// Not leaking internal error details to the client
					log.Printf("unable to update user\n")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				http.Error(w, `{"error": "email or password is incorrect"}`, http.StatusUnauthorized)
				return
			}

			// Not leaking internal error details to the client
			log.Printf("internal server error: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.SetCookie(
			w,
			&http.Cookie{
				Name:     "session",
				Value:    sessionPublicID.String(),
				Path:     "/",
				Domain:   apiAddress,
				Expires:  sessionExpirationTime,
				MaxAge:   int(sessionDuration.Seconds()),
				Secure:   true, // HTTPS only
				HttpOnly: true, // Inaccessible from JS
				// Do not send with cross site requests, but FE and BE must be on the same domain
				SameSite: http.SameSiteStrictMode,
			},
		)

		w.Header().Set("Content-Type", "application/json")

		response := PostLoginResponse{CSRFToken: csrfToken.String()}
		responseBytes, err := json.Marshal(response)
		if err != nil {
			log.Printf("internal server error: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Write(responseBytes)
	}
}

//===============================================

type GetUserResp struct {
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// GetUser handles GET /user for the requesting user only
//
// Dependency inject dbConn
func GetUser(
	dbConn *pgx.Conn,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		userID, err := apiutil.GetUserIDFromReq(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// This query must complete within 10 seconds otherwise it will timeout
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		var userName string
		var userEmail string
		var userCreatedAt time.Time

		err = database.StartTransaction(dbConn, ctx, func(tx pgx.Tx) error {

			//================================
			// Check if the user exists
			row := tx.QueryRow(
				ctx,
				`select
					"user"."name",
					"user"."email",
					"user"."created_at"
				from "user"
				where
				 	"user"."id" = $1;
				`,
				userID,
			)

			err := row.Scan(
				&userName,
				&userEmail,
				&userCreatedAt,
			)
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			// User not found or incorrect password
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, `{"error": "user not found"}`, http.StatusNotFound)
				return
			}

			// Not leaking internal error details to the client
			log.Printf("internal server error: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		response := GetUserResp{
			Name:      userName,
			Email:     userEmail,
			CreatedAt: userCreatedAt,
		}
		responseBytes, err := json.Marshal(response)
		if err != nil {
			log.Printf("internal server error: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Write(responseBytes)
	}
}
