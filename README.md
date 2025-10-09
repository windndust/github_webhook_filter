# Github Webhook Filter Server

Lightweight GO server to filter Github webhook requests and forwards only the desired ones to a configured URL

## Why:
When subscribing to Github's 'Package' event type, Github sends multiple webhook requests with no way to filter out the ones you don't care about. Example, for a repo that builds maven and docker packages, github sent 7 webhook requests: 6 for maven and 1 for CONTAINER. If you're using a service like webhookrelay.com, these extra requests quickly eat into your quota for free resources. This server aims to optimize your flow by filtering out unwanted requests and forwarding desired requests (CONTAINER package_type) to a configured URL.

## Usage:
- Server listens to port 8080
- Only 1 path is used: "/"
- Two environment variables are needed.
    - GITHUB_WEBHOOK_SECRET: This is the shared secret you created when configuring the Github Webhook. This server uses it for hmac verification
    - WEBHOOKRELAY_URL: This is the URL this server forwards the desired webhook request to

### Flag
- 'loadEnvFile': If 'true', loads environment variables from variable.env file (useful for local dev work). Defaults to true

### Exxample
```bash
go run github_webhook_filter_server.go -loadEnvFile=false
go run github_webhook_filter_server.go -loadEnvFile=true
go run github_webhook_filter_server.go
```

## Limitations
- Filtering is hardcoded to allow CONTAINER package_type requests to pass. 
- Server port is hardcoded to 8080