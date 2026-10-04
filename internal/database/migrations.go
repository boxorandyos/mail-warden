package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func (p *Postgres) ApplyMigrations(ctx context.Context, dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}

	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		files = append(files, e.Name())
	}
	slices.Sort(files)

	applied := make([]string, 0, len(files))
	for _, f := range files {
		path := filepath.Join(dir, f)
		sqlBytes, err := os.ReadFile(path)
		if err != nil {
			return applied, fmt.Errorf("read migration %s: %w", f, err)
		}
		if _, err := p.pool.Exec(ctx, string(sqlBytes)); err != nil {
			return applied, fmt.Errorf("apply migration %s: %w", f, err)
		}
		applied = append(applied, f)
	}

	return applied, nil
}
