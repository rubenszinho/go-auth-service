FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk update && apk add --no-cache git ca-certificates && update-ca-certificates

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o main ./cmd/server

FROM gcr.io/distroless/static-debian11

WORKDIR /app

COPY --from=builder /app/main .

ENV PORT=8080
ENV HOST=0.0.0.0
ENV ENV=production

EXPOSE 8080

CMD ["./main"]
