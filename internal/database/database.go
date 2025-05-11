package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
)

// ConnectToDBWithEnvVars use environment variables
//
// Intended for deployment rather than integration tests
func ConnectToDBWithEnvVars() *pgx.Conn {

	dbEnvInput := GetDBEnv()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	dbConn, err := ConnectToDB(
		dbEnvInput.DbUser,
		dbEnvInput.DbPass,
		dbEnvInput.DbHost,
		dbEnvInput.DbPort,
		dbEnvInput.DbName,
		ctx,
	)
	if err != nil {
		log.Fatalf("error connecting to database: %s", err.Error())
	}

	return dbConn

}

type DBEnv struct {
	DbUser string
	DbPass string
	DbHost string
	DbPort string
	DbName string
}

// GetDBEnv get environment variables for database connection,
//
// Cannot proceed without, reports and exits program on error
func GetDBEnv() DBEnv {

	var dbEnv DBEnv

	dbEnv.DbUser = os.Getenv("DB_USER")
	if dbEnv.DbUser == "" {
		log.Fatalf("DB_USER is not defined")
	}

	dbEnv.DbPass = os.Getenv("DB_PASS")
	if dbEnv.DbPass == "" {
		log.Fatalf("DB_PASS is not defined")
	}

	dbEnv.DbHost = os.Getenv("DB_HOST")
	if dbEnv.DbHost == "" {
		log.Fatalf("DB_HOST is not defined")
	}

	dbEnv.DbPort = os.Getenv("DB_PORT")
	if dbEnv.DbPort == "" {
		log.Fatalf("DB_PORT is not defined")
	}

	dbEnv.DbName = os.Getenv("DB_NAME")
	if dbEnv.DbName == "" {
		log.Fatalf("DB_NAME is not defined")
	}

	return dbEnv
}

// ConnectToDB connects to a postgres database and checks the connection via dbConn.Ping()
func ConnectToDB(
	user string,
	password string,
	host string,
	port string,
	dbName string,
	context context.Context,
) (*pgx.Conn, error) {

	// postgresql://[user[:password]@][netloc][:port][/dbname]
	dbString := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s", user, password, host, port, dbName)

	dbConn, err := pgx.Connect(context, dbString)
	if err != nil {
		return nil, fmt.Errorf("Unable to connect to database: %v\n", err)
	}

	err = dbConn.Ping(context)
	if err != nil {
		return nil, fmt.Errorf("Unable to Ping the database: %v\n", err)
	}

	return dbConn, nil
}

// StartTransaction creates a database transaction for function input func(*sql.Tx) error
// If it returns an error or panics transaction is rolled back
//
// Returns err from sqlFnClosure
func StartTransaction(
	dbConn *pgx.Conn,
	context context.Context,
	sqlFnClosure func(pgx.Tx) error,
) error {

	tx, err := dbConn.Begin(context)
	if err != nil {
		return err
	}

	// Handle when we find an error or (panic) inside a transaction
	defer func() {
		panicErr := recover()

		if panicErr != nil {
			// a panic occurred, rollback and re-panic
			tx.Rollback(context)
			panic(panicErr)

		} else if err != nil {
			// something went wrong, rollback
			tx.Rollback(context)

		} else {
			// all good, commit
			err = tx.Commit(context)
		}
	}()

	err = sqlFnClosure(tx)
	return err
}
