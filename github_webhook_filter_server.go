package main

import (
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
	"strings"

	"github.com/joho/godotenv"
)

type PackageEvent struct {
	Package struct {
		PackageType string `json:"package_type"`
	} `json:"package"`
}

var webhookSecret string
var relayURL string
var loadEnvFile = flag.Bool("loadEnvFile", true, "Load environment variables from .env file")

func init() {
	flag.Parse()
	if *loadEnvFile {
		if err := godotenv.Load("variables.env"); err != nil {
			log.Printf("Error when loading environment variables: %v\n", err)
		}
	}
	webhookSecret = os.Getenv("GITHUB_WEBHOOK_SECRET")
	relayURL = os.Getenv("WEBHOOKRELAY_URL")
	if webhookSecret == "" || relayURL == "" {
		log.Fatal("Missing required environment variables")
	}
	log.Printf("Webhook shared secret loaded")
	log.Printf("URL: %s\n", relayURL)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("/", handler)
	log.Printf("Starting github webhooks filter server, listening on 8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func handler(responseWriter http.ResponseWriter, request *http.Request) {
	log.Printf("********************")
	log.Printf("Received %s request from %s", request.Method, request.RemoteAddr)
	if err := logRequest(request.Header); err != "" {
		respondError(responseWriter, string(err), http.StatusBadRequest)
		return
	}
	handleRequest(responseWriter, request)
	log.Printf("Finished processing request")
	log.Printf("********************")
}

func handleRequest(responseWriter http.ResponseWriter, request *http.Request) {
	requestBody := readRequest(request.Body)
	headerSignature := request.Header.Get("X-Hub-Signature-256")
	if !verifySignature(headerSignature, requestBody) {
		respondError(responseWriter, "Invalid Signature", http.StatusUnauthorized)
		return
	}
	log.Printf("Signature Match! %s\n", headerSignature)

	var event PackageEvent
	if err := json.Unmarshal(requestBody, &event); err != nil {
		logLine := fmt.Sprintf("Failed to parse JSON: %v", err)
		respondError(responseWriter, logLine, http.StatusBadRequest)
		return
	}

	if ptype := event.Package.PackageType; ptype != "CONTAINER" {
		logLine := fmt.Sprintf("Filtered out package_type %s! No forward to relay", ptype)
		respondError(responseWriter, logLine, http.StatusBadRequest)
		return
	}

	log.Printf("Request passed filter! Sending to relay")

	req, _ := http.NewRequestWithContext(request.Context(), "POST", relayURL, strings.NewReader(string(requestBody)))
	req.Header.Set("User-Agent", "Go WebHook Filter")
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	httpResponse, err := client.Do(req)
	if err != nil {
		logLine := fmt.Sprintf("Error sending request: %v\n", err)
		respondError(responseWriter, logLine, http.StatusBadGateway)
	}
	defer httpResponse.Body.Close()

	log.Printf("Downstream relay responded with code: %d", httpResponse.StatusCode)

	if statusCode := httpResponse.StatusCode; statusCode < 200 || statusCode >= 300 {
		http.Error(responseWriter, fmt.Sprintf("Error - Relay returned status: %d", statusCode), http.StatusBadGateway)
	}
	responseWriter.WriteHeader(http.StatusOK)
}

func logRequest(headers http.Header) string {
	requestId := headers.Get("X-GitHub-Delivery")
	eventType := headers.Get("X-GitHub-Event")
	if requestId == "" || eventType == "" {
		errorLine := fmt.Sprintf("Either missing requestId: (%s) or eventType: (%s) and will not process request further", requestId, eventType)
		return errorLine
	}
	log.Printf("Processing request with id: (%s) and event type: (%s)\n", requestId, eventType)
	return ""
}

func readRequest(reader io.ReadCloser) []byte {
	requestBody, error := io.ReadAll(reader)
	if error != nil {
		log.Printf("Error when reading request body: %v", error.Error())
	}
	return requestBody
}

func verifySignature(headerSignature string, requestBodyToHash []byte) bool {
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(requestBodyToHash)
	calculated := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(calculated), []byte(headerSignature))
}

func respondError(responseWriter http.ResponseWriter, msg string, code int) {
	log.Printf("%s", msg)
	http.Error(responseWriter, msg, code)
}
