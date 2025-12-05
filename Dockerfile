# Build stage
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /app

# Install git and ca-certificates (needed for fetching dependencies)
RUN apk update && apk add --no-cache git ca-certificates && update-ca-certificates

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with optimizations for Railway
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o main ./cmd/server

# Final stage - use distroless for security and smaller size
FROM gcr.io/distroless/static-debian11

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/main .

# Set environment variables for Railway
ENV PORT=8080
ENV HOST=0.0.0.0
ENV ENV=production

# Expose port (Railway will override this)
EXPOSE 8080

# Run the application
CMD ["./main"]
