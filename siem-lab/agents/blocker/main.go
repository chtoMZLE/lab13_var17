package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	natsgo "github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

type Verdict struct {
	IncidentID      string   `json:"incident_id"`
	Verdict         string   `json:"verdict"`
	ThreatLevel     string   `json:"threat_level"`
	MitreTactic     string   `json:"mitre_tactic"`
	RecommendedAction string `json:"recommended_action"`
	Reasoning       string   `json:"reasoning"`
	BlockIPs        []string `json:"block_ips"`
	AlertSOC        bool     `json:"alert_soc"`
}

type FirewallRule struct {
	Command         string `json:"command"`
	TargetIP        string `json:"target_ip"`
	DurationMinutes int    `json:"duration_minutes"`
	Reason          string `json:"reason"`
}

type BlockingNotification struct {
	SendAlert bool   `json:"send_alert"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
}

type BlockingResult struct {
	IncidentID   string               `json:"incident_id"`
	ActionTaken  string               `json:"action_taken"`
	FirewallRules []FirewallRule      `json:"firewall_rules"`
	Notification BlockingNotification `json:"notification"`
}

func initTracer() func() {
	jaegerURL := os.Getenv("JAEGER_URL")
	if jaegerURL == "" {
		jaegerURL = "http://localhost:14268/api/traces"
	}
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(jaegerURL)))
	if err != nil {
		log.Printf("[BLOCKER] jaeger init error: %v", err)
		return func() {}
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("blocker"),
		)),
	)
	otel.SetTracerProvider(tp)
	return func() { tp.Shutdown(context.Background()) }
}

func processVerdict(ctx context.Context, v Verdict, rdb *redis.Client) BlockingResult {
	result := BlockingResult{
		IncidentID:    v.IncidentID,
		FirewallRules: []FirewallRule{},
	}

	switch {
	case v.Verdict == "TRUE_POSITIVE" && (v.ThreatLevel == "HIGH" || v.ThreatLevel == "CRITICAL"):
		result.ActionTaken = "blocked"
		duration := 1440
		if v.ThreatLevel == "CRITICAL" {
			duration = 4320
		}
		for _, ip := range v.BlockIPs {
			rdb.SAdd(ctx, "blocked_ips", ip)
			result.FirewallRules = append(result.FirewallRules, FirewallRule{
				Command:         fmt.Sprintf("iptables -A INPUT -s %s -j DROP", ip),
				TargetIP:        ip,
				DurationMinutes: duration,
				Reason:          fmt.Sprintf("Брутфорс: TRUE_POSITIVE, уровень %s", v.ThreatLevel),
			})
		}
		result.Notification = BlockingNotification{
			SendAlert: true,
			Severity:  v.ThreatLevel,
			Message:   fmt.Sprintf("IP %v заблокированы на %d минут. Причина: %s.", v.BlockIPs, duration/60, v.Reasoning),
		}

	case v.Verdict == "TRUE_POSITIVE" && v.ThreatLevel == "MEDIUM":
		result.ActionTaken = "rate_limited"
		for _, ip := range v.BlockIPs {
			rdb.SAdd(ctx, "blocked_ips", ip)
			result.FirewallRules = append(result.FirewallRules, FirewallRule{
				Command:         fmt.Sprintf("iptables -A INPUT -s %s -m limit --limit 10/min -j ACCEPT", ip),
				TargetIP:        ip,
				DurationMinutes: 60,
				Reason:          "Rate limit: TRUE_POSITIVE, уровень MEDIUM",
			})
		}
		result.Notification = BlockingNotification{
			SendAlert: true,
			Severity:  "MEDIUM",
			Message:   fmt.Sprintf("IP %v ограничен по скорости.", v.BlockIPs),
		}

	case v.Verdict == "SUSPICIOUS":
		result.ActionTaken = "logged"
		result.Notification = BlockingNotification{
			SendAlert: true,
			Severity:  "LOW",
			Message:   fmt.Sprintf("Подозрительная активность зафиксирована: %s", v.Reasoning),
		}

	default:
		result.ActionTaken = "no_action"
		result.Notification = BlockingNotification{
			SendAlert: false,
			Severity:  "INFO",
			Message:   "Ложное срабатывание, действий не требуется.",
		}
	}

	return result
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
		log.Fatalf("[BLOCKER] NATS connect error: %v", err)
	}
	defer nc.Close()

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Fatalf("[BLOCKER] Redis URL parse error: %v", err)
	}
	rdb := redis.NewClient(opt)
	defer rdb.Close()

	tracer := otel.Tracer("blocker")

	_, err = nc.Subscribe("threat.verdict", func(msg *natsgo.Msg) {
		ctx, span := tracer.Start(context.Background(), "block_threat")
		defer span.End()

		var v Verdict
		if err := json.Unmarshal(msg.Data, &v); err != nil {
			log.Printf("[BLOCKER] unmarshal error: %v", err)
			return
		}

		span.SetAttributes(
			attribute.String("verdict", v.Verdict),
			attribute.String("threat_level", v.ThreatLevel),
		)

		result := processVerdict(ctx, v, rdb)
		rdb.Incr(ctx, "stats:blocker")

		data, _ := json.Marshal(result)
		nc.Publish("blocking.done", data)

		log.Printf("[BLOCKER] incident=%s action=%s ips=%v", v.IncidentID, result.ActionTaken, v.BlockIPs)
	})
	if err != nil {
		log.Fatalf("[BLOCKER] Subscribe error: %v", err)
	}

	log.Println("[BLOCKER] ожидаю вердикты на topics threat.verdict...")
	select {}
}
