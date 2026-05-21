FROM golang:1.21-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY agents/ ./agents/
RUN CGO_ENABLED=0 GOOS=linux go build -o correlator ./agents/correlator/

FROM alpine:latest
WORKDIR /app
COPY --from=builder /build/correlator .
ENV NATS_URL=nats://nats:4222
ENV REDIS_URL=redis://redis:6379
ENV JAEGER_URL=http://jaeger:14268/api/traces
CMD ["./correlator"]
