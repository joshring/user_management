package user

import (
	"api_example/internal/database"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AddUserUsingDB add user to database if they don't already exist
func AddUserUsingDB(
	dbConn *pgx.Conn,
	ctx context.Context,
	userName string,
	userEmail string,
	userPublicID uuid.UUID,
	passwordHashed string,
	timeFunc func() time.Time,
) error {

	err := database.StartTransaction(dbConn, ctx, func(tx pgx.Tx) error {

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
			userName,
			userEmail,
		)

		var userNameFromDB string
		var userEmailFromDB string

		err := row.Scan(
			&userNameFromDB,
			&userEmailFromDB,
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
			if userEmailFromDB != "" && userNameFromDB != "" {
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
			userName,
			userEmail,
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
		return err
	}

	return nil
}

// GetUserUsingDB get user from database
func GetUserUsingDB(
	dbConn *pgx.Conn,
	ctx context.Context,
	userID int,
) (string, string, time.Time, error) {

	var userName string
	var userEmail string
	var userCreatedAt time.Time

	err := database.StartTransaction(dbConn, ctx, func(tx pgx.Tx) error {

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
		return "", "", time.Time{}, err
	}

	return userName, userEmail, userCreatedAt, err
}

// LoginUsingDB login
//
// Returns userID, sessionPublicID and csrfToken
func LoginUsingDB(
	dbConn *pgx.Conn,
	ctx context.Context,
	userEmail string,
	password string,
	timeFunc func() time.Time,
	sessionDuration time.Duration,
	sessionExpirationTime time.Time,
) (int, uuid.UUID, uuid.UUID, error) {

	var passwordHashed string
	sessionPublicID := uuid.New()
	csrfToken := uuid.New()

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
		ok, err := argon2id.ComparePasswordAndHash(password, passwordHashed)
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
		return userID, sessionPublicID, csrfToken, err
	}

	return userID, sessionPublicID, csrfToken, nil
}
