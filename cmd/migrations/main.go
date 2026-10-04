package main

import (
	"context"
	"flag"
	"log"

	"github.com/boxorandyos/mail-warden/internal/database"
)

func main() {
	dsn := flag.String("dsn", "", "postgres dsn")
	dir := flag.String("dir", "./migrations", "migrations directory")
	orgID := flag.Int64("org-id", 1, "default bootstrap organization id")
	orgName := flag.String("org-name", "default", "default bootstrap organization name")
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

	applied, err := pg.ApplyMigrations(ctx, *dir)
	if err != nil {
		log.Fatalf("apply migrations: %v", err)
	}
	if err := pg.EnsureBootstrapOrg(ctx, *orgID, *orgName); err != nil {
		log.Fatalf("ensure bootstrap organization: %v", err)
	}
	log.Printf("applied %d migration file(s)", len(applied))
}
