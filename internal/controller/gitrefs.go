package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// maxRefAdvertisement bounds how much of a ref advertisement is read. A
// repository with tens of thousands of refs is still well under it.
const maxRefAdvertisement = 64 << 20

// readAdvertisedRefs fetches the refs a Git smart-HTTP server advertises for
// service (git-upload-pack or git-receive-pack) at repoURL, authenticating
// with basic auth. It returns ref name -> object id, without peeled ("^{}")
// entries. Nothing is pushed or fetched: this is the read-only discovery GET
// every git client makes first. Credentials travel only in the Authorization
// header and never appear in a returned error.
func readAdvertisedRefs(ctx context.Context, httpClient *http.Client, repoURL, service, username, password string) (map[string]string, error) {
	endpoint := strings.TrimRight(repoURL, "/") + "/info/refs?service=" + url.QueryEscape(service)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("construct ref advertisement request")
	}
	req.SetBasicAuth(username, password)
	// Some forges only answer the smart protocol to a git user agent.
	req.Header.Set("User-Agent", "git/forgejo-operator")
	req.Header.Set("Accept", "application/x-"+service+"-advertisement")
	resp, err := httpClient.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("request %s ref advertisement: %w", service, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s ref advertisement answered %d %s", service, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "application/x-"+service+"-advertisement" {
		return nil, fmt.Errorf("%s ref advertisement has content type %q, not the smart-HTTP protocol", service, contentType)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRefAdvertisement+1))
	if err != nil {
		return nil, fmt.Errorf("read %s ref advertisement: %w", service, err)
	}
	if len(data) > maxRefAdvertisement {
		return nil, fmt.Errorf("%s ref advertisement exceeds %d bytes", service, maxRefAdvertisement)
	}
	return parseRefAdvertisement(data, service)
}

// parseRefAdvertisement parses a protocol v0/v1 smart-HTTP ref advertisement:
//
//	pkt("# service=<service>\n") flush-pkt
//	[pkt("version 1\n")]
//	pkt("<oid> <ref>\0<capabilities>\n")
//	pkt("<oid> <ref>\n") ...
//	flush-pkt
//
// An empty repository advertises "<zero-oid> capabilities^{}" instead of refs.
// Peeled lines ("<oid> <ref>^{}") name the object an annotated tag points at;
// they are not refs and are skipped, so the result maps each ref to the object
// it actually names (the tag object, for an annotated tag).
func parseRefAdvertisement(data []byte, service string) (map[string]string, error) {
	r := bytes.NewReader(data)
	refs := map[string]string{}
	first := true
	for {
		payload, flush, err := readPktLine(r)
		if err != nil {
			return nil, err
		}
		if first && !flush && bytes.HasPrefix(payload, []byte("# service=")) {
			if got := strings.TrimSpace(string(payload[len("# service="):])); got != service {
				return nil, fmt.Errorf("ref advertisement is for service %q, want %q", got, service)
			}
			// The service announcement is terminated by its own flush-pkt.
			if _, flush, err = readPktLine(r); err != nil {
				return nil, err
			} else if !flush {
				return nil, errors.New("ref advertisement service header is not followed by a flush-pkt")
			}
			continue
		}
		if flush {
			return refs, nil
		}
		line := strings.TrimSuffix(string(payload), "\n")
		if first {
			first = false
			if strings.HasPrefix(line, "version ") {
				first = true
				continue
			}
			// Capabilities follow the first ref after a NUL.
			if i := strings.IndexByte(line, 0); i >= 0 {
				line = line[:i]
			}
		}
		oid, name, ok := strings.Cut(line, " ")
		if !ok || !isObjectID(oid) || name == "" {
			return nil, errors.New("malformed ref advertisement line")
		}
		if strings.HasSuffix(name, "^{}") {
			continue
		}
		refs[name] = oid
	}
}

// readPktLine reads one pkt-line. flush reports a flush-pkt ("0000").
func readPktLine(r *bytes.Reader) (payload []byte, flush bool, err error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, false, errors.New("ref advertisement ended before its flush-pkt")
	}
	length, err := strconv.ParseUint(string(header[:]), 16, 16)
	if err != nil {
		return nil, false, errors.New("malformed pkt-line length")
	}
	switch {
	case length == 0:
		return nil, true, nil
	case length < 4:
		// 0001 and 0002 are protocol v2 delimiters, never valid here.
		return nil, false, fmt.Errorf("unexpected special pkt-line %04x", length)
	}
	payload = make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, false, errors.New("truncated pkt-line")
	}
	return payload, false, nil
}

// isObjectID accepts a full SHA-1 or SHA-256 object id in lowercase hex.
func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
