package telemetry

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/dx86683-lab/protosim/internal/config"
)

// Bus coordinates asynchronous batched persistence, real-time SSE fan-out,
// scanner attribution, probe deduplication, and optional new-probe Webhooks.
type Bus struct {
	store      *Store
	attributor *Attributor
	cfgMu      sync.RWMutex
	storageCfg config.StorageConfig
	webhookCfg config.WebhookConfig

	ch          chan BatchWriteItem
	flushC      chan chan struct{}
	done        chan struct{}
	closeO      sync.Once
	dropped     atomic.Uint64
	lastDropLog atomic.Int64

	subMu sync.RWMutex
	subs  map[chan LiveMessage]struct{}

	httpClient *http.Client
}

// NewBus starts a background telemetry pipeline backed by Store.
func NewBus(store *Store, storageCfg config.StorageConfig, webhookCfg config.WebhookConfig) *Bus {
	rules, err := store.ListScannerRules()
	if err != nil {
		rules = DefaultScannerRules()
	}
	b := &Bus{
		store:      store,
		attributor: NewAttributor(rules),
		storageCfg: storageCfg,
		webhookCfg: webhookCfg,
		ch:         make(chan BatchWriteItem, 65536),
		flushC:     make(chan chan struct{}),
		done:       make(chan struct{}),
		subs:       make(map[chan LiveMessage]struct{}),
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
	go b.loop()
	return b
}

func (b *Bus) Store() *Store { return b.store }

func (b *Bus) Attributor() *Attributor { return b.attributor }

// ReloadRules refreshes the in-memory attribution rules from SQLite.
func (b *Bus) ReloadRules() error {
	rules, err := b.store.ListScannerRules()
	if err != nil {
		return err
	}
	b.attributor.Reload(rules)
	return nil
}

// UpdateRuntimeConfig updates storage & webhook toggles safely at runtime.
func (b *Bus) UpdateRuntimeConfig(storageCfg config.StorageConfig, webhookCfg config.WebhookConfig) {
	b.cfgMu.Lock()
	b.storageCfg = storageCfg
	b.webhookCfg = webhookCfg
	b.cfgMu.Unlock()
}

func (b *Bus) StorageConfig() config.StorageConfig {
	b.cfgMu.RLock()
	defer b.cfgMu.RUnlock()
	return b.storageCfg
}

func (b *Bus) WebhookConfig() config.WebhookConfig {
	b.cfgMu.RLock()
	defer b.cfgMu.RUnlock()
	return b.webhookCfg
}

// Subscribe registers a real-time SSE listener channel.
func (b *Bus) Subscribe() (<-chan LiveMessage, func()) {
	ch := make(chan LiveMessage, 128)
	b.subMu.Lock()
	b.subs[ch] = struct{}{}
	b.subMu.Unlock()

	cancel := func() {
		b.subMu.Lock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
		b.subMu.Unlock()
	}
	return ch, cancel
}

func (b *Bus) broadcast(msg LiveMessage) {
	b.subMu.RLock()
	defer b.subMu.RUnlock()
	for ch := range b.subs {
		select {
		case ch <- msg:
		default:
			// Drop for slow SSE consumers so data-plane never blocks.
		}
	}
}

func (b *Bus) enqueue(item BatchWriteItem) {
	select {
	case b.ch <- item:
	default:
		n := b.dropped.Add(1)
		now := time.Now().Unix()
		last := b.lastDropLog.Load()
		if now-last >= 5 && b.lastDropLog.CompareAndSwap(last, now) {
			logrus.Warnf("telemetry bus queue full; total dropped=%d", n)
		}
	}
}

// RecordSession persists a session open/update/close snapshot.
func (b *Bus) RecordSession(sess Session) {
	if sess.StartedAt.IsZero() {
		sess.StartedAt = time.Now().UTC()
	}
	if sess.ScannerTag == "" {
		sess.ScannerTag = b.attributor.Match(AttributionInput{
			RemoteIP: sess.RemoteIP,
			JA3:      sess.JA3,
		})
	}
	cp := sess
	b.enqueue(BatchWriteItem{Session: &cp})
	if sess.Status != "open" {
		b.broadcast(LiveMessage{
			Type:       "session",
			Timestamp:  time.Now().UTC(),
			Protocol:   sess.Protocol,
			RemoteIP:   sess.RemoteIP,
			LocalPort:  sess.LocalPort,
			ScannerTag: sess.ScannerTag,
			ProbeHash:  sess.ProbeHash,
			SessionID:  sess.ID,
			Summary:    sess.Status,
		})
	}
}

// RecordEvent records a structured protocol or transport event.
func (b *Bus) RecordEvent(ev Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	cp := ev
	b.enqueue(BatchWriteItem{Event: &cp})
	b.broadcast(LiveMessage{
		Type:      "event",
		Timestamp: ev.Timestamp,
		Protocol:  ev.Protocol,
		RemoteIP:  ev.RemoteIP,
		LocalPort: ev.LocalPort,
		SessionID: ev.SessionID,
		Summary:   ev.Summary,
	})
}

// RecordCredential records an authentication attempt (applying optional redaction).
func (b *Bus) RecordCredential(cr Credential) {
	if cr.Timestamp.IsZero() {
		cr.Timestamp = time.Now().UTC()
	}
	if cr.ScannerTag == "" {
		cr.ScannerTag = b.attributor.Match(AttributionInput{RemoteIP: cr.RemoteIP})
	}
	if b.StorageConfig().RedactCredentials && cr.Secret != "" {
		cr.Secret = "***REDACTED***"
	}
	cp := cr
	b.enqueue(BatchWriteItem{Credential: &cp})
	b.broadcast(LiveMessage{
		Type:       "credential",
		Timestamp:  cr.Timestamp,
		Protocol:   cr.Protocol,
		RemoteIP:   cr.RemoteIP,
		ScannerTag: cr.ScannerTag,
		SessionID:  cr.SessionID,
		Summary:    "auth user=" + cr.Username,
	})
}

// RecordPayload persists a bounded directional raw payload chunk when enabled.
func (b *Bus) RecordPayload(pl PayloadChunk) {
	sc := b.StorageConfig()
	if !sc.PayloadEnabled || len(pl.Data) == 0 {
		return
	}
	if pl.Timestamp.IsZero() {
		pl.Timestamp = time.Now().UTC()
	}
	data := make([]byte, len(pl.Data))
	copy(data, pl.Data)
	pl.Data = data
	cp := pl
	b.enqueue(BatchWriteItem{Payload: &cp})
}

// RecordProbeHit deduplicates an incoming first payload into the Probe Library and returns (hash, scannerTag).
func (b *Bus) RecordProbeHit(protocol, transport string, port uint16, remoteIP, ja3, sessionID string, payload []byte) (string, string) {
	hash := ComputeProbeHash(protocol, port, payload)
	tag := b.attributor.Match(AttributionInput{
		RemoteIP: remoteIP,
		JA3:      ja3,
		Payload:  payload,
	})
	cp := make([]byte, len(payload))
	copy(cp, payload)
	b.enqueue(BatchWriteItem{
		ProbeHit: &ProbeHitInput{
			Hash:       hash,
			Protocol:   protocol,
			Transport:  transport,
			Port:       port,
			Timestamp:  time.Now().UTC(),
			RemoteIP:   remoteIP,
			ScannerTag: tag,
			SessionID:  sessionID,
			Payload:    cp,
		},
	})
	return hash, tag
}

// Flush blocks until all previously enqueued items have been committed to SQLite.
func (b *Bus) Flush() {
	ack := make(chan struct{})
	select {
	case b.flushC <- ack:
		<-ack
	case <-b.done:
	}
}

// Close drains all pending items and stops the background writer cleanly.
func (b *Bus) Close() {
	b.closeO.Do(func() {
		close(b.ch)
		<-b.done
	})
}

func (b *Bus) loop() {
	defer close(b.done)

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	const maxBatchSize = 2000
	batch := make([]BatchWriteItem, 0, maxBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		newProbes, err := b.store.WriteBatch(batch)
		if err != nil {
			logrus.Errorf("telemetry batch write error: %v", err)
		}
		batch = batch[:0]
		for _, p := range newProbes {
			b.onNewProbe(p)
		}
	}

	for {
		select {
		case item, ok := <-b.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, item)
			if len(batch) >= maxBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case ack := <-b.flushC:
			// Drain any items currently buffered in b.ch
			for {
				select {
				case item, ok := <-b.ch:
					if !ok {
						flush()
						close(ack)
						return
					}
					batch = append(batch, item)
				default:
					flush()
					close(ack)
					goto next
				}
			}
		next:
		}
	}
}

func (b *Bus) onNewProbe(p Probe) {
	tag := "unknown"
	if len(p.ScannerTags) > 0 {
		tag = p.ScannerTags[0]
	}
	b.broadcast(LiveMessage{
		Type:       "new_probe",
		Timestamp:  p.FirstSeen,
		Protocol:   p.Protocol,
		LocalPort:  p.Port,
		ScannerTag: tag,
		ProbeHash:  p.Hash,
		IsNewProbe: true,
		SessionID:  p.SampleSessionID,
		Summary:    "New unique probe discovered (" + p.Hash[:12] + ")",
	})

	wh := b.WebhookConfig()
	if !wh.Enabled || !wh.OnNewProbe || wh.URL == "" {
		return
	}
	go b.sendWebhook(wh, p)
}

func (b *Bus) sendWebhook(wh config.WebhookConfig, p Probe) {
	body, err := json.Marshal(map[string]any{
		"event": "new_probe",
		"probe": p,
	})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if wh.Secret != "" {
		mac := hmac.New(sha256.New, []byte(wh.Secret))
		mac.Write(body)
		req.Header.Set("X-ProtoSim-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := b.httpClient.Do(req)
	if err != nil {
		logrus.Warnf("new_probe webhook failed: %v", err)
		return
	}
	_ = resp.Body.Close()
}
