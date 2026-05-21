package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
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

type Incident struct {
	IncidentID        string   `json:"incident_id"`
	Pattern           string   `json:"pattern"`
	Confidence        float64  `json:"confidence"`
	SourceIPs         []string `json:"source_ips"`
	AffectedHosts     []string `json:"affected_hosts"`
	EventCount        int      `json:"event_count"`
	TimeWindowSeconds int      `json:"time_window_seconds"`
	Description       string   `json:"description"`
}

func initTracer() func() {
	jaegerURL := os.Getenv("JAEGER_URL")
	if jaegerURL == "" {
		jaegerURL = "http://localhost:14268/api/traces"
	}
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(jaegerURL)))
	if err != nil {
		log.Printf("[CORRELATOR] jaeger init error: %v", err)
		return func() {}
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("correlator"),
		)),
	)
	otel.SetTracerProvider(tp)
	return func() { tp.Shutdown(context.Background()) }
}

func scanKeys(ctx context.Context, rdb *redis.Client, pattern string) ([]string, error) {
	var cursor uint64
	var keys []string
	for {
		batch, next, err := rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return keys, nil
}

func checkPatterns(ctx context.Context, rdb *redis.Client, nc *natsgo.Conn) {
	keys, err := scanKeys(ctx, rdb, "event:*")
	if err != nil {
		return
	}

	type eventSummary struct {
		SourceIP  string
		DestIP    string
		Port      int
		EventType string
	}

	var events []eventSummary
	for _, key := range keys {
		val, err := rdb.Get(ctx, key).Result()
		if err != nil {
			continue
		}
		var evt NormalizedEvent
		if err := json.Unmarshal([]byte(val), &evt); err != nil {
			continue
		}
		events = append(events, eventSummary{
			SourceIP:  evt.SourceIP,
			DestIP:    evt.DestIP,
			Port:      evt.Port,
			EventType: evt.EventType,
		})
	}

	// Паттерн 1: Брутфорс
	authByIP := map[string]int{}
	for _, e := range events {
		if e.EventType == "auth_failure" {
			authByIP[e.SourceIP]++
		}
	}
	for ip, count := range authByIP {
		if count > 5 {
			dedupKey := fmt.Sprintf("incident_sent:brute_force:%s", ip)
			if rdb.Exists(ctx, dedupKey).Val() > 0 {
				continue
			}
			rdb.Set(ctx, dedupKey, "1", 120*time.Second)
			incident := Incident{
				IncidentID:        uuid.New().String(),
				Pattern:           "brute_force",
				Confidence:        0.85,
				SourceIPs:         []string{ip},
				AffectedHosts:     []string{"unknown"},
				EventCount:        count,
				TimeWindowSeconds: 60,
				Description:       fmt.Sprintf("Обнаружен брутфорс: %d неудачных попыток входа с %s", count, ip),
			}
			publishIncident(ctx, nc, rdb, incident)
		}
	}

	// Паттерн 2: Сканирование портов
	portsByIP := map[string]map[int]bool{}
	for _, e := range events {
		if portsByIP[e.SourceIP] == nil {
			portsByIP[e.SourceIP] = map[int]bool{}
		}
		portsByIP[e.SourceIP][e.Port] = true
	}
	for ip, ports := range portsByIP {
		if len(ports) > 10 {
			dedupKey := fmt.Sprintf("incident_sent:port_scan:%s", ip)
			if rdb.Exists(ctx, dedupKey).Val() > 0 {
				continue
			}
			rdb.Set(ctx, dedupKey, "1", 120*time.Second)
			incident := Incident{
				IncidentID:        uuid.New().String(),
				Pattern:           "port_scan",
				Confidence:        0.75,
				SourceIPs:         []string{ip},
				AffectedHosts:     []string{"unknown"},
				EventCount:        len(ports),
				TimeWindowSeconds: 60,
				Description:       fmt.Sprintf("Обнаружено сканирование портов: %d портов с %s", len(ports), ip),
			}
			publishIncident(ctx, nc, rdb, incident)
		}
	}

	// Паттерн 3: DDoS
	countByDest := map[string]map[string]bool{}
	for _, e := range events {
		if countByDest[e.DestIP] == nil {
			countByDest[e.DestIP] = map[string]bool{}
		}
		countByDest[e.DestIP][e.SourceIP] = true
	}
	for destIP, srcIPs := range countByDest {
		if len(srcIPs) > 20 {
			dedupKey := fmt.Sprintf("incident_sent:ddos:%s", destIP)
			if rdb.Exists(ctx, dedupKey).Val() > 0 {
				continue
			}
			rdb.Set(ctx, dedupKey, "1", 120*time.Second)
			ips := make([]string, 0, len(srcIPs))
			for ip := range srcIPs {
				ips = append(ips, ip)
			}
			incident := Incident{
				IncidentID:        uuid.New().String(),
				Pattern:           "ddos",
				Confidence:        0.90,
				SourceIPs:         ips,
				AffectedHosts:     []string{destIP},
				EventCount:        len(srcIPs),
				TimeWindowSeconds: 60,
				Description:       fmt.Sprintf("Обнаружена DDoS-атака: %d источников на %s", len(srcIPs), destIP),
			}
			publishIncident(ctx, nc, rdb, incident)
		}
	}
}

func publishIncident(ctx context.Context, nc *natsgo.Conn, rdb *redis.Client, incident Incident) {
	data, err := json.Marshal(incident)
	if err != nil {
		log.Printf("[CORRELATOR] marshal error: %v", err)
		return
	}
	if err := nc.Publish("incidents.new", data); err != nil {
		log.Printf("[CORRELATOR] publish error: %v", err)
		return
	}
	rdb.Incr(ctx, "stats:correlator")
	rdb.RPush(ctx, "incidents:history", string(data))
	rdb.LTrim(ctx, "incidents:history", -100, -1)
	log.Printf("[CORRELATOR] инцидент опубликован: pattern=%s source_ips=%v count=%d",
		incident.Pattern, incident.SourceIPs, incident.EventCount)
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
		log.Fatalf("[CORRELATOR] NATS connect error: %v", err)
	}
	defer nc.Close()

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("[CORRELATOR] Redis URL parse error: %v", err)
	}
	rdb := redis.NewClient(opt)
	defer rdb.Close()

	tracer := otel.Tracer("correlator")

	_, err = nc.QueueSubscribe("logs.normalized", "correlators", func(msg *natsgo.Msg) {
		ctx, span := tracer.Start(context.Background(), "correlate_event")
		defer span.End()

		// Уменьшаем счётчик очереди: сообщение принято в обработку
		rdb.Decr(ctx, "queue:depth")

		var evt NormalizedEvent
		if err := json.Unmarshal(msg.Data, &evt); err != nil {
			log.Printf("[CORRELATOR] unmarshal error: %v", err)
			return
		}

		span.SetAttributes(
			attribute.String("event.type", evt.EventType),
			attribute.String("source.ip", evt.SourceIP),
		)

		// Сохраняем событие в Redis с TTL 60 секунд
		key := fmt.Sprintf("event:%s", evt.ID)
		if err := rdb.Set(ctx, key, string(msg.Data), 60*time.Second).Err(); err != nil {
			log.Printf("[CORRELATOR] redis set error: %v", err)
		}

		checkPatterns(ctx, rdb, nc)
	})
	if err != nil {
		log.Fatalf("[CORRELATOR] Subscribe error: %v", err)
	}

	// Подписка на аукционные задачи (логика в auction.go)
	if _, err := nc.Subscribe("tasks.auction", func(msg *natsgo.Msg) {
		handleAuction(msg, nc)
	}); err != nil {
		log.Printf("[CORRELATOR] auction subscribe error: %v", err)
	}

	log.Println("[CORRELATOR] ожидаю события на topics logs.normalized...")
	select {}
}
