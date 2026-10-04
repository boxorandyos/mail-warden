package rspamd

import (
	"bufio"
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"github.com/boxorandyos/mail-warden/internal/database"
)

var urlPattern = regexp.MustCompile(`https?://[^\s<>"']+`)

func ExtractURLObservations(raw []byte, maliciousHint bool, confidence string) []database.URLObservation {
	matches := urlPattern.FindAll(raw, -1)
	seen := map[string]struct{}{}
	out := make([]database.URLObservation, 0, len(matches))
	for _, m := range matches {
		u := string(m)
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		parsed, err := url.Parse(u)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		out = append(out, database.URLObservation{
			URL:        u,
			Domain:     strings.ToLower(parsed.Hostname()),
			Malicious:  maliciousHint,
			Confidence: confidence,
		})
	}
	return out
}

func ExtractAttachmentObservations(raw []byte) []database.AttachmentObservation {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	mediatype, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(strings.ToLower(mediatype), "multipart/") {
		return nil
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	return readMultipartAttachments(mr)
}

func readMultipartAttachments(mr *multipart.Reader) []database.AttachmentObservation {
	out := make([]database.AttachmentObservation, 0, 4)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		filename := part.FileName()
		if filename == "" {
			continue
		}
		contentType := part.Header.Get("Content-Type")
		size := int64(0)
		scanner := bufio.NewScanner(part)
		for scanner.Scan() {
			size += int64(len(scanner.Bytes()))
		}
		out = append(out, database.AttachmentObservation{
			Filename:    filename,
			ContentType: firstNonEmpty(contentType, "application/octet-stream"),
			SizeBytes:   size,
			Suspicious:  suspiciousAttachment(filename, contentType),
		})
	}
	return out
}

func suspiciousAttachment(filename, contentType string) bool {
	lName := strings.ToLower(filename)
	lType := strings.ToLower(contentType)
	if strings.HasSuffix(lName, ".exe") || strings.HasSuffix(lName, ".js") || strings.HasSuffix(lName, ".vbs") || strings.HasSuffix(lName, ".scr") {
		return true
	}
	return strings.Contains(lType, "application/x-msdownload")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
