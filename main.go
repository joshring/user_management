package main

import (
	"api_example/internal/database"
	"api_example/internal/server"
)

func main() {
	dbConn := database.ConnectToDBWithEnvVars()
	server.StartServer(dbConn)
}
