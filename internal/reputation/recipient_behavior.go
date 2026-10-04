package reputation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type RecipientBehavior struct {
	InvalidRatio      float64 `json:"invalid_ratio"`
	EnumerationLikely bool    `json:"enumeration_likely"`
}

type RecipientBehaviorDetector struct {
	rdb      *redis.Client
	keySpace string
}

func NewRecipientBehaviorDetector(redisAddr string) *RecipientBehaviorDetector {
	return &RecipientBehaviorDetector{
		rdb: redis.NewClient(&redis.Options{
			Addr: redisAddr,
			DB:   0,
		}),
		keySpace: "mailwarden",
	}
}

func (d *RecipientBehaviorDetector) Close() error {
	return d.rdb.Close()
}

func (d *RecipientBehaviorDetector) Observe(ctx context.Context, sender string, recipients []string, validSet map[string]bool) (RecipientBehavior, error) {
	sender = strings.ToLower(strings.TrimSpace(sender))
	if sender == "" {
		sender = "unknown"
	}
	bucket := time.Now().UTC().Format("2006010215")
	totalKey := d.key("rcpt", "total", sender, bucket)
	invalidKey := d.key("rcpt", "invalid", sender, bucket)
	patternKey := d.key("rcpt", "pattern", sender, bucket)

	total := 0
	invalid := 0
	pipe := d.rdb.TxPipeline()
	for _, rcpt := range recipients {
		norm := strings.ToLower(strings.TrimSpace(rcpt))
		if norm == "" {
			continue
		}
		total++
		if !validSet[norm] {
			invalid++
			pipe.SAdd(ctx, patternKey, normalizeLocalPart(norm))
		}
	}
	if total > 0 {
		pipe.IncrBy(ctx, totalKey, int64(total))
		pipe.IncrBy(ctx, invalidKey, int64(invalid))
	}
	pipe.Expire(ctx, totalKey, 2*time.Hour)
	pipe.Expire(ctx, invalidKey, 2*time.Hour)
	pipe.Expire(ctx, patternKey, 2*time.Hour)
	if _, err := pipe.Exec(ctx); err != nil {
		return RecipientBehavior{}, fmt.Errorf("recipient behavior redis pipeline: %w", err)
	}

	totalCount, err := d.rdb.Get(ctx, totalKey).Int64()
	if err != nil && err != redis.Nil {
		return RecipientBehavior{}, fmt.Errorf("read total count: %w", err)
	}
	invalidCount, err := d.rdb.Get(ctx, invalidKey).Int64()
	if err != nil && err != redis.Nil {
		return RecipientBehavior{}, fmt.Errorf("read invalid count: %w", err)
	}
	patternCount, err := d.rdb.SCard(ctx, patternKey).Result()
	if err != nil {
		return RecipientBehavior{}, fmt.Errorf("read pattern count: %w", err)
	}
	var ratio float64
	if totalCount > 0 {
		ratio = float64(invalidCount) / float64(totalCount)
	}
	likely := ratio >= 0.3 && patternCount >= 20 && totalCount >= 30
	return RecipientBehavior{
		InvalidRatio:      ratio,
		EnumerationLikely: likely,
	}, nil
}

func normalizeLocalPart(address string) string {
	at := strings.Index(address, "@")
	if at <= 0 {
		return address
	}
	return address[:at]
}

func (d *RecipientBehaviorDetector) key(parts ...string) string {
	return d.keySpace + ":" + strings.Join(parts, ":")
}
