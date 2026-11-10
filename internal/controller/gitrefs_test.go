package controller

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func pktLine(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func TestParseRefAdvertisementUploadPack(t *testing.T) {
	const (
		head   = "159661cdced35f355adf2eee4758204c135bd5a8"
		tagObj = "bf727897ea0ad441021cf4b678d07967e99cc509"
		peeled = "1f6cb3fbb270f64697e27a8caf7b0d29eb268ade"
		branch = "e8243992c4b8e949c355e1409bcb042150652b32"
	)
	data := pktLine("# service=git-upload-pack\n") + "0000" +
		pktLine(head+" HEAD\x00multi_ack thin-pack side-band symref=HEAD:refs/heads/main agent=git/github\n") +
		pktLine(head+" refs/heads/main\n") +
		pktLine(branch+" refs/heads/feature/x\n") +
		pktLine(tagObj+" refs/tags/v1\n") +
		pktLine(peeled+" refs/tags/v1^{}\n") +
		"0000"
	refs, err := parseRefAdvertisement([]byte(data), "git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"HEAD":                 head,
		"refs/heads/main":      head,
		"refs/heads/feature/x": branch,
		// The annotated tag keeps its tag object id; the peeled line is dropped.
		"refs/tags/v1": tagObj,
	}
	if !reflect.DeepEqual(refs, want) {
		t.Fatalf("refs=%v\nwant %v", refs, want)
	}
}

func TestParseRefAdvertisementEmptyRepository(t *testing.T) {
	data := pktLine("# service=git-receive-pack\n") + "0000" +
		pktLine(strings.Repeat("0", 40)+" capabilities^{}\x00report-status delete-refs\n") + "0000"
	refs, err := parseRefAdvertisement([]byte(data), "git-receive-pack")
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("an empty repository advertised refs: %v", refs)
	}
}

func TestParseRefAdvertisementRejectsMalformed(t *testing.T) {
	oid := strings.Repeat("a", 40)
	for name, data := range map[string]string{
		"wrong service":   pktLine("# service=git-upload-pack\n") + "0000" + "0000",
		"no final flush":  pktLine("# service=git-receive-pack\n") + "0000" + pktLine(oid+" refs/heads/main\x00caps\n"),
		"truncated":       pktLine("# service=git-receive-pack\n") + "0000" + "0040" + oid,
		"bad length":      "zzzz",
		"bad oid":         pktLine("# service=git-receive-pack\n") + "0000" + pktLine("nothex refs/heads/main\x00caps\n") + "0000",
		"v2 delimiter":    pktLine("# service=git-receive-pack\n") + "0000" + "0001" + "0000",
		"header no flush": pktLine("# service=git-receive-pack\n") + pktLine(oid+" refs/heads/main\n") + "0000",
		"html login page": "<html>",
	} {
		if _, err := parseRefAdvertisement([]byte(data), "git-receive-pack"); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func TestReadAdvertisedRefsRequest(t *testing.T) {
	oid := strings.Repeat("b", 40)
	var gotURL, gotUser, gotPass string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotURL = r.URL.String()
		gotUser, gotPass, _ = r.BasicAuth()
		resp := response(http.StatusOK, pktLine("# service=git-receive-pack\n")+"0000"+pktLine(oid+" refs/heads/main\x00report-status\n")+"0000")
		resp.Header.Set("Content-Type", "application/x-git-receive-pack-advertisement")
		return resp, nil
	})
	refs, err := readAdvertisedRefs(context.Background(), &http.Client{Transport: transport}, "https://github.com/o/r.git/", "git-receive-pack", "x-access-token", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if gotURL != "https://github.com/o/r.git/info/refs?service=git-receive-pack" || gotUser != "x-access-token" || gotPass != "secret-token" {
		t.Fatalf("url=%s user=%s passwordMatch=%t", gotURL, gotUser, gotPass == "secret-token")
	}
	if refs["refs/heads/main"] != oid {
		t.Fatalf("refs=%v", refs)
	}
}

func TestReadAdvertisedRefsRejectsNonSmartResponse(t *testing.T) {
	for name, build := range map[string]func() *http.Response{
		"unauthorized": func() *http.Response { return response(http.StatusUnauthorized, "") },
		"dumb http": func() *http.Response {
			resp := response(http.StatusOK, "aaaa\trefs/heads/main\n")
			resp.Header.Set("Content-Type", "text/plain")
			return resp
		},
	} {
		transport := roundTripFunc(func(*http.Request) (*http.Response, error) { return build(), nil })
		_, err := readAdvertisedRefs(context.Background(), &http.Client{Transport: transport}, "https://github.com/o/r.git", "git-receive-pack", "u", "secret-token")
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "secret-token") {
			t.Errorf("%s: error leaks the credential: %v", name, err)
		}
	}
}
