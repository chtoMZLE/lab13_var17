package main

import (
	"encoding/json"
	"log"

	natsgo "github.com/nats-io/nats.go"
)

// handleAuction отвечает на запрос аукциона задач.
// Оркестратор публикует задачу в tasks.auction, агенты отвечают ставкой в tasks.bids.
// Агент с минимальной cost получает назначение через tasks.assigned.{agent_id}.
func handleAuction(msg *natsgo.Msg, nc *natsgo.Conn) {
	var task map[string]interface{}
	if err := json.Unmarshal(msg.Data, &task); err != nil {
		log.Printf("[CORRELATOR] auction unmarshal error: %v", err)
		return
	}
	taskID, _ := task["task_id"].(string)
	bid := map[string]interface{}{
		"task_id":  taskID,
		"agent_id": "correlator-1",
		"cost":     0.3,
		"reason":   "загрузка 30%",
	}
	data, err := json.Marshal(bid)
	if err != nil {
		log.Printf("[CORRELATOR] auction marshal error: %v", err)
		return
	}
	if err := nc.Publish("tasks.bids", data); err != nil {
		log.Printf("[CORRELATOR] auction publish error: %v", err)
	}
}
