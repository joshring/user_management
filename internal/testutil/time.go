package testutil

import (
	"log"
	"time"
)

// TimeFuncForTest gives a fixed time for deterministic tests
func TimeFuncForTest() time.Time {

	timeFixed, err := time.Parse(time.RFC3339, "2025-05-10T09:50:50Z")
	if err != nil {
		log.Fatal(err)
	}
	return timeFixed
}
