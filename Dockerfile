FROM golang:1.23.1-alpine3.20 AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY . .
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o dtrack-webhook main.go

FROM alpine:3.20.0

RUN apk add --no-cache ca-certificates

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /app/dtrack-webhook /usr/local/bin/dtrack-webhook

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/dtrack-webhook"]