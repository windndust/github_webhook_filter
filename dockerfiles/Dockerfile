#Official Dockerfile example from https://hub.docker.com/_/golang/

#Specifies the base image to use (and pulls down if not already cached)
FROM golang:1.26

#conventional location for source code in Linux File System Hierarchy Standard (FHS)
WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download

#standard copy-all command for dockerfile, .dockerignore is used to exclude specifiesd files from the copy
#since no directory app exists by default in /usr/local/bin, the build output is named app
COPY . .
RUN go build -v -o /usr/local/bin/app ./...

#runtime command to start the app
CMD ["app"]