package main

import (
	"strings"
	"testing"
)

func TestNormalizeLog_AuthFailure(t *testing.T) {
	raw := "Failed password for root from 1.2.3.4 port 22"
	result := normalizeLog(raw)
	if result.EventType != "auth_failure" {
		t.Errorf("ожидалось auth_failure, получено %s", result.EventType)
	}
	if result.Severity != "WARNING" {
		t.Errorf("ожидалось severity WARNING, получено %s", result.Severity)
	}
	if result.SourceIP != "1.2.3.4" {
		t.Errorf("ожидалось source_ip 1.2.3.4, получено %s", result.SourceIP)
	}
	if result.Port != 22 {
		t.Errorf("ожидалось port 22, получено %d", result.Port)
	}
}

func TestNormalizeLog_PortScan(t *testing.T) {
	raw := "port scan detected from 10.0.0.1 nmap"
	result := normalizeLog(raw)
	if result.EventType != "port_scan" {
		t.Errorf("ожидалось port_scan, получено %s", result.EventType)
	}
	if result.Severity != "ERROR" {
		t.Errorf("ожидалось severity ERROR, получено %s", result.Severity)
	}
}

func TestNormalizeLog_DDoS(t *testing.T) {
	raw := "DDoS attack flood detected from 8.8.8.8"
	result := normalizeLog(raw)
	if result.EventType != "ddos" {
		t.Errorf("ожидалось ddos, получено %s", result.EventType)
	}
	if result.Severity != "CRITICAL" {
		t.Errorf("ожидалось severity CRITICAL, получено %s", result.Severity)
	}
}

func TestNormalizeLog_Normal(t *testing.T) {
	raw := "Accepted password for alice from 192.168.1.1 port 22"
	result := normalizeLog(raw)
	if result.EventType != "normal" {
		t.Errorf("ожидалось normal, получено %s", result.EventType)
	}
	if result.Severity != "INFO" {
		t.Errorf("ожидалось severity INFO, получено %s", result.Severity)
	}
}

func TestNormalizeLog_Unknown(t *testing.T) {
	raw := "some random log message"
	result := normalizeLog(raw)
	if result.EventType != "unknown" {
		t.Errorf("ожидалось unknown, получено %s", result.EventType)
	}
}

func TestNormalizeLog_HasID(t *testing.T) {
	raw := "Failed password for root from 1.2.3.4 port 22"
	result := normalizeLog(raw)
	if result.ID == "" {
		t.Error("ожидался непустой ID")
	}
}

func TestNormalizeLog_RawPreserved(t *testing.T) {
	raw := "Failed password for root from 1.2.3.4 port 22"
	result := normalizeLog(raw)
	if !strings.Contains(result.Raw, "Failed password") {
		t.Errorf("поле raw должно содержать оригинальный лог, получено: %s", result.Raw)
	}
}

func TestNormalizeLog_AuthenticationFailure(t *testing.T) {
	raw := "authentication failure; user=bob from 172.16.0.1"
	result := normalizeLog(raw)
	if result.EventType != "auth_failure" {
		t.Errorf("ожидалось auth_failure для 'authentication failure', получено %s", result.EventType)
	}
}
