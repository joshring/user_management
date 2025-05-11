package testutil

import (
	"api_example/internal/database"
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// ConnectToDBForTest this is specifically designed for local integration tests only
//
// Do not use outside tests
func ConnectToDBForTest(t *testing.T) *pgx.Conn {

	dbEnvInput := database.DBEnv{
		DbUser: "postgres",
		DbPass: "password",
		DbHost: "localhost",
		DbPort: "5432",
		DbName: "dbname",
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	dbConn, err := database.ConnectToDB(
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

	tablesList := []string{
		"session",
		"user",
	}

	// Empty tables prior to running the test
	for _, tableName := range tablesList {

		tableNameIdent := pgx.Identifier{tableName}

		_, err := dbConn.Exec(ctx, fmt.Sprintf("truncate %s cascade;", tableNameIdent.Sanitize()))
		if err != nil {
			log.Fatal(err)
		}
	}

	t.Cleanup(
		func() {
			dbConn.Close(ctx)
		},
	)

	return dbConn

}
