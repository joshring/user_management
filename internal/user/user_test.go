package user_test

import (
	"api_example/internal/testutil"
	"api_example/internal/user"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// authorizationHeader helper for base64 encoding Authorization header contents
func authorizationHeader(username string, password string) string {
	header := fmt.Sprintf("%s:%s", username, password)
	headerBase64 := base64.StdEncoding.EncodeToString([]byte(header))

	return fmt.Sprintf("Basic %s", headerBase64)

}

func TestGetUser(t *testing.T) {

	require := require.New(t)
	dbConn := testutil.ConnectToDBForTest(t)
	server := testutil.StartTestServer(t, dbConn, testutil.TimeFuncForTest)

	//====================================
	// Create the user we need to login with

	name := "joe blogs"
	email := "joe.blogs@example.com"
	password := "Password is dead secure!332"

	response, err := http.Post(
		fmt.Sprintf("%s/user", server.URL),
		"application/json",
		bytes.NewReader(
			[]byte(`
			{
				"name": "`+name+`",
			 	"email": "`+email+`",
				"password": "`+password+`"
			}
		`)),
	)
	require.Nil(err)
	defer response.Body.Close()

	//==========================
	// Is the login user response as expected?
	require.Equal(http.StatusOK, response.StatusCode)

	responseBytes, err := io.ReadAll(response.Body)
	require.Nil(err)

	var postUserResp user.PostUserResp

	err = json.Unmarshal(responseBytes, &postUserResp)
	require.Nil(err)

	require.Equal(
		user.PostUserResp{
			PublicID: postUserResp.PublicID, // dynamic value
			Name:     name,
			Email:    email,
		},
		postUserResp,
	)

	//====================================
	// Login with the newly created user

	request, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/login", server.URL),
		nil,
	)
	require.Nil(err)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", authorizationHeader(email, password))

	response, err = http.DefaultClient.Do(request)
	require.Nil(err)
	require.Equal(http.StatusOK, response.StatusCode)

	//====================================
	// Extract out session and CSRF token
	defer response.Body.Close()

	responseBytes, err = io.ReadAll(response.Body)
	require.Nil(err)

	var postLoginResponse user.PostLoginResponse
	err = json.Unmarshal(responseBytes, &postLoginResponse)
	require.Nil(err)

	csrfToken := postLoginResponse.CSRFToken

	//====================================
	// Get the user

	request, err = http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/user", server.URL),
		nil,
	)
	require.Nil(err)

	// Add the CSRF token and session cookie to the request
	request.Header.Set("csrf_token", csrfToken)
	request.AddCookie(response.Cookies()[0])

	response, err = http.DefaultClient.Do(request)
	require.Nil(err)
	require.Equal(http.StatusOK, response.StatusCode)

	defer response.Body.Close()

	testutil.CheckValue(
		t,
		response,
		http.StatusOK,
		user.GetUserResp{
			Name:      name,
			Email:     email,
			CreatedAt: testutil.TimeFuncForTest(),
		},
	)

}

func TestGetUserUnauthorised(t *testing.T) {

	require := require.New(t)
	dbConn := testutil.ConnectToDBForTest(t)
	server := testutil.StartTestServer(t, dbConn, testutil.TimeFuncForTest)

	//====================================
	// Create the user we need to login with

	name := "joe blogs"
	email := "joe.blogs@example.com"
	password := "Password is dead secure!332"

	response, err := http.Post(
		fmt.Sprintf("%s/user", server.URL),
		"application/json",
		bytes.NewReader(
			[]byte(`
			{
				"name": "`+name+`",
			 	"email": "`+email+`",
				"password": "`+password+`"
			}
		`)),
	)
	require.Nil(err)
	defer response.Body.Close()

	//====================================
	// Get the user - using the wrong values - should fail

	request, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/user", server.URL),
		nil,
	)
	require.Nil(err)

	// Add the CSRF token and session cookie to the request, with the wrong values
	request.Header.Set("csrf_token", "WRONG VALUE HERE")
	request.AddCookie(&http.Cookie{Name: "session", Value: "ANOTHER WRONG VALUE"})

	response, err = http.DefaultClient.Do(request)
	require.Nil(err)
	require.Equal(http.StatusUnauthorized, response.StatusCode)

}

func TestLogin(t *testing.T) {

	require := require.New(t)
	dbConn := testutil.ConnectToDBForTest(t)
	server := testutil.StartTestServer(t, dbConn, testutil.TimeFuncForTest)

	//====================================
	// Create the user we need to login with

	name := "joe blogs"
	email := "joe.blogs@example.com"
	password := "Password is dead secure!332"

	response, err := http.Post(
		fmt.Sprintf("%s/user", server.URL),
		"application/json",
		bytes.NewReader(
			[]byte(`
			{
				"name": "`+name+`",
			 	"email": "`+email+`",
				"password": "`+password+`"
			}
		`)),
	)
	require.Nil(err)
	defer response.Body.Close()

	//==========================
	// Is the login user response as expected?
	require.Equal(http.StatusOK, response.StatusCode)

	responseBytes, err := io.ReadAll(response.Body)
	require.Nil(err)

	var postUserResp user.PostUserResp

	err = json.Unmarshal(responseBytes, &postUserResp)
	require.Nil(err)

	require.Equal(
		user.PostUserResp{
			PublicID: postUserResp.PublicID, // dynamic value
			Name:     name,
			Email:    email,
		},
		postUserResp,
	)
	//====================================
	// Login with the newly created user

	request, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/login", server.URL),
		nil,
	)
	require.Nil(err)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", authorizationHeader(email, password))

	response, err = http.DefaultClient.Do(request)
	require.Nil(err)
	defer response.Body.Close()

	require.Equal(http.StatusOK, response.StatusCode)

	//=================================
	// Validate cookie properties
	require.Len(response.Cookies(), 1)

	require.Equal("session", response.Cookies()[0].Name)
	require.Equal(true, response.Cookies()[0].HttpOnly)
	require.Equal(true, response.Cookies()[0].Secure)
	require.Equal(http.SameSiteStrictMode, response.Cookies()[0].SameSite)

	sessionDuration := time.Minute * 60 * 24
	sessionExpirationTime := testutil.TimeFuncForTest().Add(sessionDuration)

	require.Equal(int(sessionDuration.Seconds()), response.Cookies()[0].MaxAge)
	require.Equal(sessionExpirationTime, response.Cookies()[0].Expires)
	//=================================
	// The cookie value is the sessionPublicID
	sessionPublicID := response.Cookies()[0].Value

	//=================================
	// Check the database's stored information matches correctly
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	row := dbConn.QueryRow(
		ctx,
		`select
			"session"."csrf_token",
			"user"."email"
		from "session"
		join "user" on "user"."id" = "session"."user_id"
		where
			"session"."public_id" = $1
		`,
		sessionPublicID,
	)

	var csrfTokenFromDB string
	var userEmailFromDB string

	err = row.Scan(
		&csrfTokenFromDB,
		&userEmailFromDB,
	)
	require.Nil(err)

	require.Equal(email, userEmailFromDB)

	testutil.CheckValue(
		t,
		response,
		http.StatusOK,
		user.PostLoginResponse{CSRFToken: csrfTokenFromDB},
	)

}

func TestLoginLockedAfter10Fails(t *testing.T) {

	require := require.New(t)
	dbConn := testutil.ConnectToDBForTest(t)
	server := testutil.StartTestServer(t, dbConn, testutil.TimeFuncForTest)

	//====================================
	// Create the user we need to login with

	name := "joe blogs"
	email := "joe.blogs@example.com"
	password := "Password is dead secure!332"

	response, err := http.Post(
		fmt.Sprintf("%s/user", server.URL),
		"application/json",
		bytes.NewReader(
			[]byte(`
			{
				"name": "`+name+`",
			 	"email": "`+email+`",
				"password": "`+password+`"
			}
		`)),
	)
	require.Nil(err)
	defer response.Body.Close()

	//==========================
	// Is the login user response as expected?
	require.Equal(http.StatusOK, response.StatusCode)

	responseBytes, err := io.ReadAll(response.Body)
	require.Nil(err)

	var postUserResp user.PostUserResp

	err = json.Unmarshal(responseBytes, &postUserResp)
	require.Nil(err)

	require.Equal(
		user.PostUserResp{
			PublicID: postUserResp.PublicID, // dynamic value
			Name:     name,
			Email:    email,
		},
		postUserResp,
	)
	//====================================
	// Login successfully with the newly created user

	log.Println("valid /login request")

	request, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/login", server.URL),
		nil,
	)
	require.Nil(err)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", authorizationHeader(email, password))

	response, err = http.DefaultClient.Do(request)
	require.Nil(err)
	defer response.Body.Close()

	require.Equal(http.StatusOK, response.StatusCode)

	//====================================
	// Deliberatly fail to login 10 times consecutively
	for index := range 10 {

		log.Printf("invalid /login request %d\n", index+1)

		request, err := http.NewRequest(
			http.MethodPost,
			fmt.Sprintf("%s/login", server.URL),
			nil,
		)
		require.Nil(err)

		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", authorizationHeader(email, "WRONG PASSWORD"))

		response, err = http.DefaultClient.Do(request)
		require.Nil(err)

		require.Equal(http.StatusUnauthorized, response.StatusCode)

	}

	//====================================
	// After failing to login 10 times, previously successful login details now deactivated

	log.Println("attempting the valid /login request again, should now be deactivated")

	request, err = http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/login", server.URL),
		nil,
	)
	require.Nil(err)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", authorizationHeader(email, password))

	response, err = http.DefaultClient.Do(request)
	require.Nil(err)
	defer response.Body.Close()

	require.Equal(http.StatusUnauthorized, response.StatusCode)

}

func TestPostUserFailures(t *testing.T) {

	require := require.New(t)
	dbConn := testutil.ConnectToDBForTest(t)
	server := testutil.StartTestServer(t, dbConn, testutil.TimeFuncForTest)

	//====================================
	// Password is not long enough, return bad request

	name := "joe blogs"
	email := "joe.blogs@example.com"
	password := "Password is dead secure!332"

	response, err := http.Post(
		fmt.Sprintf("%s/user", server.URL),
		"application/json",
		bytes.NewReader(
			[]byte(`
			{
				"name": "`+name+`",
			 	"email": "`+email+`",
				"password": "ShortPass"
			}
		`)),
	)
	require.Nil(err)
	defer response.Body.Close()

	testutil.CheckErr(
		t,
		response,
		http.StatusBadRequest,
		"password must 12 or more characters long",
	)

	//====================================
	// name is missing, return bad request

	response, err = http.Post(
		fmt.Sprintf("%s/user", server.URL),
		"application/json",
		bytes.NewReader(
			[]byte(`
			{
			 	"email": "`+email+`",
				"password": "`+password+`"
			}
		`)),
	)
	require.Nil(err)
	defer response.Body.Close()

	testutil.CheckErr(
		t,
		response,
		http.StatusBadRequest,
		"name not provided",
	)

	//====================================
	// email is invalid, return bad request

	response, err = http.Post(
		fmt.Sprintf("%s/user", server.URL),
		"application/json",
		bytes.NewReader(
			[]byte(`
			{
				"name": "`+name+`",
			 	"email": "nopeexamplecom",
				"password": "`+password+`"
			}
		`)),
	)
	require.Nil(err)
	defer response.Body.Close()

	testutil.CheckErr(
		t,
		response,
		http.StatusBadRequest,
		"mail: missing '@' or angle-addr",
	)
}

func TestPostUserDuplicateRejected(t *testing.T) {

	require := require.New(t)
	dbConn := testutil.ConnectToDBForTest(t)
	server := testutil.StartTestServer(t, dbConn, testutil.TimeFuncForTest)

	//====================================
	// First try should work fine

	name := "joe blogs"
	email := "joe.blogs@example.com"
	password := "Password is dead secure!332"

	response, err := http.Post(
		fmt.Sprintf("%s/user", server.URL),
		"application/json",
		bytes.NewReader(
			[]byte(`
			{
				"name": "`+name+`",
			 	"email": "`+email+`",
				"password": "`+password+`"
			}
		`)),
	)
	require.Nil(err)
	defer response.Body.Close()

	//==========================
	// Is the login user response as expected?
	require.Equal(http.StatusOK, response.StatusCode)

	responseBytes, err := io.ReadAll(response.Body)
	require.Nil(err)

	var postUserResp user.PostUserResp

	err = json.Unmarshal(responseBytes, &postUserResp)
	require.Nil(err)

	require.Equal(
		user.PostUserResp{
			PublicID: postUserResp.PublicID, // dynamic value
			Name:     name,
			Email:    email,
		},
		postUserResp,
	)

	//====================================
	// Second try should return http.StatusOK but not perform the insert

	response, err = http.Post(
		fmt.Sprintf("%s/user", server.URL),
		"application/json",
		bytes.NewReader(
			[]byte(`
			{
				"name": "`+name+`",
			 	"email": "`+email+`",
				"password": "`+password+`"
			}
		`)),
	)
	require.Nil(err)
	defer response.Body.Close()

	//==========================
	// Is the login user response as expected?
	require.Equal(http.StatusOK, response.StatusCode)

	responseBytes, err = io.ReadAll(response.Body)
	require.Nil(err)

	err = json.Unmarshal(responseBytes, &postUserResp)
	require.Nil(err)

	require.Equal(
		user.PostUserResp{
			PublicID: postUserResp.PublicID, // dynamic value
			Name:     name,
			Email:    email,
		},
		postUserResp,
	)

	//================================
	// Validate only a single user was added to the database (yes there's also a unique constraint)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	row := dbConn.QueryRow(
		ctx,
		`select
			count(*)
		from "user"
		where
			"user"."name" = $1
			and "user"."email" = $2
		`,
		"joe blogs",
		"joe.blogs@example.com",
	)

	var numUsers int

	err = row.Scan(
		&numUsers,
	)
	require.Nil(err)

	require.Equal(1, numUsers)

}

func TestPostUser(t *testing.T) {

	require := require.New(t)
	dbConn := testutil.ConnectToDBForTest(t)
	server := testutil.StartTestServer(t, dbConn, testutil.TimeFuncForTest)

	//====================================
	// Password is OK

	password := "Password is dead secure!332"
	name := "joe blogs"
	email := "joe.blogs@example.com"

	response, err := http.Post(
		fmt.Sprintf("%s/user", server.URL),
		"application/json",
		bytes.NewReader(
			[]byte(`
			{
				"name": "`+name+`",
			 	"email": "`+email+`",
				"password": "`+password+`"
			}
		`)),
	)
	require.Nil(err)
	defer response.Body.Close()

	//==========================
	// Is the login user response as expected?
	require.Equal(http.StatusOK, response.StatusCode)

	responseBytes, err := io.ReadAll(response.Body)
	require.Nil(err)

	var postUserResp user.PostUserResp

	err = json.Unmarshal(responseBytes, &postUserResp)
	require.Nil(err)

	require.Equal(
		user.PostUserResp{
			PublicID: postUserResp.PublicID, // dynamic value
			Name:     name,
			Email:    email,
		},
		postUserResp,
	)

	//================================
	// Validate the entry was added to the database
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	row := dbConn.QueryRow(
		ctx,
		`select
			"user"."name",
			"user"."email",
			"user"."created_at"
		from "user"
		where
			"user"."name" = $1
			and "user"."email" = $2
		`,
		"joe blogs",
		"joe.blogs@example.com",
	)

	var userNameFromDB string
	var userEmailFromDB string
	var createdAtFromDB time.Time

	err = row.Scan(
		&userNameFromDB,
		&userEmailFromDB,
		&createdAtFromDB,
	)
	require.Nil(err)

	require.Equal(name, userNameFromDB)
	require.Equal(email, userEmailFromDB)
	require.Equal(testutil.TimeFuncForTest(), createdAtFromDB)
}
