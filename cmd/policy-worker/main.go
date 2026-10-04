package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/boxorandyos/mail-warden/internal/database"
)

func main() {
	dsn := flag.String("dsn", "", "postgres dsn")
	interval := flag.Duration("interval", 5*time.Minute, "decay interval")
	flag.Parse()

	if *dsn == "" {
		log.Fatal("dsn is required")
	}

	ctx := context.Background()
	pg, err := database.NewPostgres(ctx, *dsn)
	if err != nil {
		log.Fatalf("connect postgres: %v", err)
	}
	defer pg.Close()

	log.Printf("policy-worker started (interval=%s)", interval.String())
	t := time.NewTicker(*interval)
	defer t.Stop()

	for range t.C {
		if _, err := pg.Pool().Exec(ctx, `
			UPDATE reputation_entities
			   SET current_score = current_score * 0.995,
			       updated_at = NOW()
			 WHERE updated_at < NOW() - INTERVAL '1 hour'
		`); err != nil {
			log.Printf("reputation decay cycle failed: %v", err)
		} else {
			log.Println("reputation decay cycle complete")
		}

		if _, err := pg.Pool().Exec(ctx, `
			UPDATE cluster_nodes
			   SET status = 'stale',
			       updated_at = NOW()
			 WHERE last_seen_at IS NOT NULL
			   AND last_seen_at < NOW() - INTERVAL '2 minute'
			   AND status = 'online'
		`); err != nil {
			log.Printf("cluster node stale mark failed: %v", err)
		}

		if _, err := pg.Pool().Exec(ctx, `
			DELETE FROM user_sessions
			 WHERE expires_at < NOW() - INTERVAL '1 day'
			    OR revoked_at < NOW() - INTERVAL '30 day'
		`); err != nil {
			log.Printf("session cleanup failed: %v", err)
		}
	}
}
