package database

import (
	"context"
	"fmt"
)

type AuthResult struct {
	SPF   string
	DKIM  string
	DMARC string
	ARC   string
}

type URLObservation struct {
	URL        string
	Domain     string
	Malicious  bool
	Confidence string
}

type AttachmentObservation struct {
	Filename    string
	ContentType string
	SizeBytes   int64
	Suspicious  bool
}

func (p *Postgres) InsertAuthenticationResult(ctx context.Context, messageID int64, result AuthResult) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO authentication_results (message_id, spf, dkim, dmarc, arc)
		VALUES ($1, $2, $3, $4, $5)
	`, messageID, result.SPF, result.DKIM, result.DMARC, result.ARC)
	if err != nil {
		return fmt.Errorf("insert authentication result: %w", err)
	}
	return nil
}

func (p *Postgres) InsertURLObservations(ctx context.Context, messageID int64, urls []URLObservation) error {
	for _, u := range urls {
		_, err := p.pool.Exec(ctx, `
			INSERT INTO url_observations (message_id, url, domain, malicious, confidence)
			VALUES ($1, $2, $3, $4, $5)
		`, messageID, u.URL, u.Domain, u.Malicious, u.Confidence)
		if err != nil {
			return fmt.Errorf("insert url observation: %w", err)
		}
	}
	return nil
}

func (p *Postgres) InsertAttachmentObservations(ctx context.Context, messageID int64, attachments []AttachmentObservation) error {
	for _, a := range attachments {
		_, err := p.pool.Exec(ctx, `
			INSERT INTO attachment_observations (message_id, filename, content_type, size_bytes, suspicious)
			VALUES ($1, $2, $3, $4, $5)
		`, messageID, a.Filename, a.ContentType, a.SizeBytes, a.Suspicious)
		if err != nil {
			return fmt.Errorf("insert attachment observation: %w", err)
		}
	}
	return nil
}
