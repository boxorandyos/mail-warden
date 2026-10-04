package reputation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type OutboundLimits struct {
	RecipientsPerHour    int
	UniqueDomainsPerHour int
}

type OutboundObservation struct {
	MessagesLastHour      int64   `json:"messages_last_hour"`
	RecipientsLastHour    int64   `json:"recipients_last_hour"`
	UniqueDomainsLastHour int64   `json:"unique_domains_last_hour"`
	RecipientDiversity    float64 `json:"recipient_diversity"`
	VelocityLevel         string  `json:"velocity_level"`
}

type OutboundCounters struct {
	rdb      *redis.Client
	keySpace string
}

func NewOutboundCounters(redisAddr string) *OutboundCounters {
	client := redis.NewClient(&redis.Options{
		Addr: redisAddr,
		DB:   0,
	})
	return &OutboundCounters{
		rdb:      client,
		keySpace: "mailwarden",
	}
}

func (c *OutboundCounters) Close() error {
	return c.rdb.Close()
}

func (c *OutboundCounters) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

func (c *OutboundCounters) ObserveOutbound(ctx context.Context, sender string, recipients []string, limits OutboundLimits) (OutboundObservation, error) {
	bucket := time.Now().UTC().Format("2006010215")
	msgKey := c.key("outbound", "msg", sender, bucket)
	rcptKey := c.key("outbound", "rcpt", sender, bucket)
	domainKey := c.key("outbound", "domain", sender, bucket)

	pipe := c.rdb.TxPipeline()
	msgCmd := pipe.Incr(ctx, msgKey)
	pipe.Expire(ctx, msgKey, 2*time.Hour)

	var domainList []string
	for _, rcpt := range recipients {
		if rcpt == "" {
			continue
		}
		pipe.SAdd(ctx, rcptKey, strings.ToLower(strings.TrimSpace(rcpt)))
		if d := recipientDomain(rcpt); d != "" {
			domainList = append(domainList, d)
		}
	}
	pipe.Expire(ctx, rcptKey, 2*time.Hour)
	if len(domainList) > 0 {
		pipe.SAdd(ctx, domainKey, domainList)
	}
	pipe.Expire(ctx, domainKey, 2*time.Hour)
	if _, err := pipe.Exec(ctx); err != nil {
		return OutboundObservation{}, fmt.Errorf("redis pipeline execute: %w", err)
	}

	recipientsCount, err := c.rdb.SCard(ctx, rcptKey).Result()
	if err != nil {
		return OutboundObservation{}, fmt.Errorf("redis scard recipients: %w", err)
	}
	domainCount, err := c.rdb.SCard(ctx, domainKey).Result()
	if err != nil {
		return OutboundObservation{}, fmt.Errorf("redis scard domains: %w", err)
	}

	obs := OutboundObservation{
		MessagesLastHour:      msgCmd.Val(),
		RecipientsLastHour:    recipientsCount,
		UniqueDomainsLastHour: domainCount,
	}
	if recipientsCount > 0 {
		obs.RecipientDiversity = float64(domainCount) / float64(recipientsCount)
	}
	obs.VelocityLevel = classifyVelocity(obs, limits)
	return obs, nil
}

func classifyVelocity(obs OutboundObservation, limits OutboundLimits) string {
	if limits.RecipientsPerHour <= 0 {
		limits.RecipientsPerHour = 5000
	}
	if limits.UniqueDomainsPerHour <= 0 {
		limits.UniqueDomainsPerHour = 500
	}

	if obs.RecipientsLastHour >= int64(limits.RecipientsPerHour) || obs.UniqueDomainsLastHour >= int64(limits.UniqueDomainsPerHour) {
		return "critical"
	}
	if obs.RecipientsLastHour >= int64(float64(limits.RecipientsPerHour)*0.7) ||
		obs.UniqueDomainsLastHour >= int64(float64(limits.UniqueDomainsPerHour)*0.7) {
		return "high"
	}
	if obs.RecipientsLastHour >= int64(float64(limits.RecipientsPerHour)*0.4) ||
		obs.UniqueDomainsLastHour >= int64(float64(limits.UniqueDomainsPerHour)*0.4) {
		return "elevated"
	}
	return "normal"
}

func recipientDomain(address string) string {
	address = strings.TrimSpace(strings.ToLower(address))
	at := strings.LastIndex(address, "@")
	if at <= 0 || at+1 >= len(address) {
		return ""
	}
	return address[at+1:]
}

func (c *OutboundCounters) key(parts ...string) string {
	return c.keySpace + ":" + strings.Join(parts, ":")
}
