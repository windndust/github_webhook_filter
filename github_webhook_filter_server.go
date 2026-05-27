package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type PackageEvent struct {
	Package struct {
		PackageType string `json:"package_type"`
	} `json:"package"`
}

type GatewayHealthResponse struct {
	Status           string                 `json:"status"`
	UpstreamResponse map[string]interface{} `json:"upstreamresponse"`
}

var webhookSecret string
var relayURL string
var loadEnvFile = flag.Bool("loadEnvFile", true, "Load environment variables from .env file")
var client *http.Client

func main() {
	configSetup()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleGetHealth)
	mux.HandleFunc("GET /gateway-health", handleGetGatewayHealth)
	mux.HandleFunc("GET /", handleHeadAndGet)
	mux.HandleFunc("POST /", handler)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Printf("Starting github webhooks filter server, listening on 8080")
	log.Fatal(server.ListenAndServe())
}

func configSetup() {
	flag.Parse()
	if *loadEnvFile {
		if err := godotenv.Load("variables.env"); err != nil {
			log.Printf("Error loading environment variables from variables.env: %v", err)
			log.Printf("Attempting load from OS env variables")
		}
	}

	webhookSecret = getEnvVar("GITHUB_WEBHOOK_SECRET", true, "")
	log.Printf("Github Webhook shared secret loaded")

	relayURL = getEnvVar("WEBHOOKRELAY_URL", true, "")
	relayURL = addSlashToURLEndIfMissing()
	log.Printf("Webhook Relay URL: %s", relayURL)

	httpClientTimeout := getEnvVar("HTTP_CLIENT_TIMEOUT", false, "15")

	if timeout, err := strconv.Atoi(httpClientTimeout); err != nil {
		log.Printf("Error parsing HTTP_CLIENT_TIMEOUT into int. Using default of 15")
		timeout = 15
	} else {
		log.Printf("Timeout: %d", timeout)
		client = &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		}
	}
}

func getEnvVar(varName string, required bool, defaultVal string) string {
	v := os.Getenv(varName)
	if v == "" && required {
		log.Fatalf("Missing required environment variable %s", varName)
	} else if v == "" && !required {
		log.Printf("Optional environment variable is empty %s", varName)
	}
	if v == "" && defaultVal != "" {
		log.Printf("Using default value, %s, for environment variable %s", defaultVal, varName)
		return defaultVal
	} else if v == "" && defaultVal == "" {
		log.Printf("No default value for environment variable %s", varName)
	}
	return v
}

func addSlashToURLEndIfMissing() string {
	length := len(relayURL)
	index := strings.LastIndex(relayURL, "/")
	if length-1 != index {
		return relayURL + "/"
	}
	return relayURL
}

func handleGetHealth(responseWriter http.ResponseWriter, request *http.Request) {
	if printLog := request.Header.Get("log"); printLog != "" && strings.EqualFold(printLog, "true") {
		log.Printf("***** Local health checked *****")
		log.Printf("***** Host: %s *****", request.Host)
	}
	responseWriter.WriteHeader(http.StatusOK)
	responseWriter.Write([]byte("OK"))
}

func handleGetGatewayHealth(responseWriter http.ResponseWriter, request *http.Request) {
	log.Printf("***** Checking Gateway Health *****")
	log.Printf("***** Host: %s *****", request.Host)

	var healthURL = relayURL + "health"
	newRequest, err := http.NewRequestWithContext(request.Context(), "GET", healthURL, nil)
	if err != nil {
		respondError(responseWriter, fmt.Errorf("%w", err), http.StatusInternalServerError)
		return
	}

	newRequest.Header.Set("User-Agent", "Go WebHook Filter")
	newRequest.Header.Set("Content-Type", "application/json")

	httpResponse, err := client.Do(newRequest)
	if err != nil {
		respondError(responseWriter, fmt.Errorf("Error when sending request %w", err), http.StatusBadGateway)
		return
	}

	defer httpResponse.Body.Close()

	responseWriter.WriteHeader(httpResponse.StatusCode)
	respBytes, err := readBody(httpResponse.Body)
	if err != nil {
		respondError(responseWriter, err, http.StatusInternalServerError)
		return
	}

	log.Printf("Upstream gatway health check result: status code: %s, body: %s", httpResponse.Status, string(respBytes))

	var upstreamData map[string]interface{}
	if err := unmarshalJson(respBytes, &upstreamData); err != nil {
		respondError(responseWriter, err, http.StatusInternalServerError)
		return
	}

	jsonResponse := GatewayHealthResponse{
		Status:           "ok",
		UpstreamResponse: upstreamData,
	}

	if err := json.NewEncoder(responseWriter).Encode(jsonResponse); err != nil {
		respondError(responseWriter, err, http.StatusInternalServerError)
		return
	}
}

func readBody(reader io.ReadCloser) ([]byte, error) {
	defer reader.Close()

	body, error := io.ReadAll(reader)
	if error != nil {
		return nil, fmt.Errorf("failed to read request body: %w", error)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("empty request body")
	}

	return body, nil
}

func unmarshalJson(bytes []byte, v any) error {
	if len(bytes) == 0 {
		return fmt.Errorf("empty or nil JSON data")
	}

	if err := json.Unmarshal(bytes, &v); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}

func handleHeadAndGet(responseWriter http.ResponseWriter, request *http.Request) {
	log.Printf("********************")
	log.Printf("Handling ghost %s to /", request.Method)
	log.Printf("Header Host: %s ", request.Host)
	for key, valuesArray := range request.Header {
		log.Printf("Header: %s = %s", key, valuesArray)
	}
	log.Printf("Finished processing request")
	log.Printf("********************")
	responseWriter.WriteHeader(http.StatusOK)
}

func handler(responseWriter http.ResponseWriter, request *http.Request) {
	log.Printf("********************")
	log.Printf("Received %s request from %s", request.Method, request.RemoteAddr)
	log.Printf("Header Host: %s", request.Host)
	defer func() {
		log.Printf("Finished processing request")
		log.Printf("********************")
	}()

	if err := validateAndLogRequest(request.Header); err != nil {
		respondError(responseWriter, err, http.StatusBadRequest)
		return
	}

	requestBody, err := readBody(request.Body)
	if err != nil {
		respondError(responseWriter, err, http.StatusInternalServerError)
		return
	}
	headerSignature := request.Header.Get("X-Hub-Signature-256")
	if err := verifySignature(headerSignature, requestBody); err != nil {
		respondError(responseWriter, err, http.StatusUnauthorized)
		return
	}
	log.Printf("Signature Match! %s", headerSignature)

	handleGithubWebhook(responseWriter, request, requestBody)
}

func validateAndLogRequest(headers http.Header) error {
	requestId := headers.Get("X-GitHub-Delivery")
	eventType := headers.Get("X-GitHub-Event")
	if requestId == "" || eventType == "" {
		return fmt.Errorf("Either missing requestId: (%s) or eventType: (%s) and will not process request further", requestId, eventType)
	}
	log.Printf("Processing request with id: (%s) and event type: (%s)", requestId, eventType)
	return nil
}

func verifySignature(headerSignature string, requestBodyToHash []byte) error {
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(requestBodyToHash)
	calculated := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if hmac.Equal([]byte(calculated), []byte(headerSignature)) {
		return nil
	}
	return fmt.Errorf("Header X-Hub-Signature-256 doesn't match signature calculated from body")
}

func respondError(responseWriter http.ResponseWriter, error error, code int) {
	log.Printf("%s", error.Error())
	http.Error(responseWriter, error.Error(), code)
}

func handleGithubWebhook(responseWriter http.ResponseWriter, request *http.Request, requestBody []byte) {
	//parse json
	var event PackageEvent
	if err := unmarshalJson(requestBody, &event); err != nil {
		respondError(responseWriter, err, http.StatusInternalServerError)
		return
	}

	//filter out wrong type of package type
	if packageType := event.Package.PackageType; packageType != "CONTAINER" {
		respondError(responseWriter, fmt.Errorf("Filtered out package_type %s! No forward to relay", packageType), http.StatusNoContent)
		return
	}
	log.Printf("package_type CONTAINER passed filter! Sending to relay")

	//make http request to relay
	var deployURL = relayURL + "deploy"
	newRequest, err := http.NewRequestWithContext(request.Context(), "POST", deployURL, bytes.NewBuffer(requestBody))
	if err != nil {
		respondError(responseWriter, err, http.StatusInternalServerError)
		return
	}
	for key, valuesArray := range request.Header {
		for _, value := range valuesArray {
			newRequest.Header.Set(key, value)
		}
	}
	newRequest.Header.Set("User-Agent", "Go WebHook Filter")
	newRequest.Header.Set("Content-Type", "application/json")

	httpResponse, err := client.Do(newRequest)
	if err != nil {
		respondError(responseWriter, fmt.Errorf("Error sending request: %w", err), http.StatusBadGateway)
		return
	}
	defer httpResponse.Body.Close()
	log.Printf("Upstream relay responded with code: %d", httpResponse.StatusCode)

	//prepare response
	if statusCode := httpResponse.StatusCode; statusCode < 200 || statusCode >= 300 {
		respondError(responseWriter, fmt.Errorf("Error - Relay returned status: %d", statusCode), http.StatusBadGateway)
		return
	}
	log.Print("Responding with success 200")
	responseWriter.WriteHeader(http.StatusOK)
	responseWriter.Write([]byte("package_type:CONTAINER passed the filter on Github Webhook Filter server hosted at onrender.com. Forwarded to relay."))
}
