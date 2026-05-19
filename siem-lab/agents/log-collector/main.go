package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	natsgo "github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

type NormalizedEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SourceIP  string    `json:"source_ip"`
	DestIP    string    `json:"dest_ip"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	EventType string    `json:"event_type"`
	Severity  string    `json:"severity"`
	Username  string    `json:"username"`
	Raw       string    `json:"raw"`
}

var (
	ipRegex   = regexp.MustCompile(`from\s+(\d+\.\d+\.\d+\.\d+)`)
	portRegex = regexp.MustCompile(`port\s+(\d+)`)
	userRegex = regexp.MustCompile(`for\s+(\S+)\s+from`)
	tsRegex   = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})`)
)

func normalizeLog(raw string) NormalizedEvent {
	evt := NormalizedEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		SourceIP:  "0.0.0.0",
		DestIP:    "0.0.0.0",
		Port:      0,
		Protocol:  "tcp",
		EventType: "unknown",
		Severity:  "INFO",
		Raw:       raw,
	}

	if m := tsRegex.FindStringSubmatch(raw); len(m) > 1 {
		if t, err := time.Parse("2006-01-02T15:04:05", m[1]); err == nil {
			evt.Timestamp = t
		}
	}
	if m := ipRegex.FindStringSubmatch(raw); len(m) > 1 {
		evt.SourceIP = m[1]
	}
	if m := portRegex.FindStringSubmatch(raw); len(m) > 1 {
		if p, err := strconv.Atoi(m[1]); err == nil {
			evt.Port = p
		}
	}
	if m := userRegex.FindStringSubmatch(raw); len(m) > 1 {
		evt.Username = m[1]
	}

	switch {
	case contains(raw, "Failed password") || contains(raw, "authentication failure"):
		evt.EventType = "auth_failure"
		evt.Severity = "WARNING"
	case contains(raw, "port scan") || contains(raw, "nmap"):
		evt.EventType = "port_scan"
		evt.Severity = "ERROR"
	case contains(raw, "DDoS") || contains(raw, "flood"):
		evt.EventType = "ddos"
		evt.Severity = "CRITICAL"
	case contains(raw, "Accepted password") || contains(raw, "session opened"):
		evt.EventType = "normal"
		evt.Severity = "INFO"
	}

	return evt
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}

func initTracer() func() {
	jaegerURL := os.Getenv("JAEGER_URL")
	if jaegerURL == "" {
		jaegerURL = "http://localhost:14268/api/traces"
	}
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(jaegerURL)))
	if err != nil {
		log.Printf("[LOG-COLLECTOR] jaeger init error: %v", err)
		return func() {}
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("log-collector"),
		)),
	)
	otel.SetTracerProvider(tp)
	return func() { tp.Shutdown(context.Background()) }
}

func main() {
	shutdown := initTracer()
	defer shutdown()

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = natsgo.DefaultURL
	}
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "redis://localhost:6379"
	}

	nc, err := natsgo.Connect(natsURL)
	if err != nil {
		log.Fatalf("[LOG-COLLECTOR] NATS connect error: %v", err)
	}
	defer nc.Close()

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("[LOG-COLLECTOR] Redis URL parse error: %v", err)
	}
	rdb := redis.NewClient(opt)
	defer rdb.Close()

	tracer := otel.Tracer("log-collector")

	_, err = nc.Subscribe("logs.raw", func(msg *natsgo.Msg) {
		raw := string(msg.Data)
		ctx, span := tracer.Start(context.Background(), "process_log")
		defer span.End()

		evt := normalizeLog(raw)
		span.SetAttributes(
			attribute.String("event.type", evt.EventType),
			attribute.String("source.ip", evt.SourceIP),
		)

		data, _ := json.Marshal(evt)
		if err := nc.Publish("logs.normalized", data); err != nil {
			log.Printf("[LOG-COLLECTOR] publish error: %v", err)
			return
		}

		rdb.Incr(ctx, "stats:log_collector")
		log.Printf("[LOG-COLLECTOR] id=%s event_type=%s source_ip=%s", evt.ID, evt.EventType, evt.SourceIP)
	})
	if err != nil {
		log.Fatalf("[LOG-COLLECTOR] Subscribe error: %v", err)
	}

	log.Println("[LOG-COLLECTOR] ожидаю логи на topics logs.raw...")
	select {}
}
