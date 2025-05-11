package testutil

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// API error response
type errResponse struct {
	Error string `json:"error"`
}

// CheckErr asserts the returned status code and error is as expected
func CheckErr(
	t *testing.T,
	response *http.Response,
	expectedStatusCode int,
	expectedErrStr string,
) {
	require := require.New(t)

	require.Equal(expectedStatusCode, response.StatusCode)

	responseBytes, err := io.ReadAll(response.Body)
	require.Nil(err)

	var responseFound errResponse

	err = json.Unmarshal(responseBytes, &responseFound)
	require.Nil(err)

	expectedRespErr := errResponse{Error: expectedErrStr}
	require.Equal(expectedRespErr, responseFound)

}

// CheckValue asserts the returned status code and value is as expected, generic over the expectedValue's type
func CheckValue[T any](
	t *testing.T,
	response *http.Response,
	expectedStatusCode int,
	expectedValue T,
) {
	require := require.New(t)

	require.Equal(expectedStatusCode, response.StatusCode)

	responseBytes, err := io.ReadAll(response.Body)
	require.Nil(err)

	var responseFound T

	err = json.Unmarshal(responseBytes, &responseFound)
	require.Nil(err)

	require.Equal(expectedValue, responseFound)

}
