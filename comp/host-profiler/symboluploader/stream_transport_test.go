// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build linux

package symboluploader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func streamTestRequest(ctx context.Context, url string) func(io.Reader, string) (*http.Request, error) {
	return func(body io.Reader, contentType string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
		if err == nil {
			req.Header.Set("Content-Type", contentType)
		}
		return req, err
	}
}

func streamTestProducer(payload []byte) func(*multipart.Writer) error {
	return func(mw *multipart.Writer) error {
		part, err := mw.CreateFormFile("elf_symbol_file", "elf_symbol_file")
		if err != nil {
			return err
		}
		_, err = part.Write(payload)
		return err
	}
}

func streamTestResponse(code int) *http.Response {
	return &http.Response{StatusCode: code, Status: http.StatusText(code), Body: http.NoBody, Header: make(http.Header)}
}

func TestMultipartStreamPlainBody(t *testing.T) {
	t.Parallel()
	type received struct {
		body []byte
		ct   string
		ce   string
		err  error
	}
	requests := make(chan received, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		requests <- received{body: body, ct: req.Header.Get("Content-Type"), ce: req.Header.Get("Content-Encoding"), err: err}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte("ELF payload\x00"), 100000)
	require.NoError(t, sendMultipartStream(ctx, server.Client(), streamTestRequest(ctx, server.URL), streamTestProducer(payload)))
	got := <-requests
	require.NoError(t, got.err)
	require.Empty(t, got.ce, "streaming must not add HTTP content encoding")
	_, params, err := mime.ParseMediaType(got.ct)
	require.NoError(t, err)
	mr := multipart.NewReader(bytes.NewReader(got.body), params["boundary"])
	part, err := mr.NextPart()
	require.NoError(t, err)
	require.Equal(t, "elf_symbol_file", part.FormName())
	data, err := io.ReadAll(part)
	require.NoError(t, err)
	require.Equal(t, payload, data)
	_, err = mr.NextPart()
	require.ErrorIs(t, err, io.EOF)
}

func TestMultipartStreamCompleteBodyWithoutExtraEOFRead(t *testing.T) {
	t.Parallel()
	for _, missingBytes := range []int{0, 1} {
		t.Run(fmt.Sprintf("missing_%d_bytes", missingBytes), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			payload := []byte("complete ELF payload")
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				_, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
				if err != nil {
					return nil, err
				}
				var expected bytes.Buffer
				mw := multipart.NewWriter(&expected)
				if err := mw.SetBoundary(params["boundary"]); err != nil {
					return nil, err
				}
				if err := streamTestProducer(payload)(mw); err != nil {
					return nil, err
				}
				if err := mw.Close(); err != nil {
					return nil, err
				}
				// Consume the complete multipart body without another EOF read,
				// or deliberately stop one byte short.
				if _, err := io.CopyN(io.Discard, req.Body, int64(expected.Len()-missingBytes)); err != nil {
					return nil, err
				}
				return streamTestResponse(http.StatusOK), nil
			})}
			err := sendMultipartStream(ctx, client, streamTestRequest(ctx, "http://intake"), streamTestProducer(payload))
			if missingBytes == 0 {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "incomplete request")
			}
		})
	}
}

func TestMultipartStreamDestinationFailures(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"transport", "http_error", "partial_read_then_error", "premature_success"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch failure {
				case "transport":
					return nil, errors.New("offline")
				case "http_error":
					return streamTestResponse(http.StatusRequestEntityTooLarge), nil
				case "partial_read_then_error":
					if _, err := io.CopyN(io.Discard, req.Body, 64<<10); err != nil {
						return nil, err
					}
					return streamTestResponse(http.StatusRequestEntityTooLarge), nil
				default:
					return streamTestResponse(http.StatusOK), nil
				}
			})}
			err := sendMultipartStream(ctx, client, streamTestRequest(ctx, "http://intake"), streamTestProducer(make([]byte, 2<<20)))
			require.Error(t, err, "a failed destination must keep the upload retryable")
		})
	}
}

func TestMultipartStreamSourceFailure(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		_, err := io.Copy(io.Discard, req.Body)
		return streamTestResponse(http.StatusOK), err
	})}
	failure := errors.New("source read failed")
	err := sendMultipartStream(ctx, client, streamTestRequest(ctx, "http://intake"), func(mw *multipart.Writer) error {
		if err := streamTestProducer([]byte("partial ELF"))(mw); err != nil {
			return err
		}
		return failure
	})
	require.ErrorIs(t, err, failure)
}

func TestMultipartStreamCancellationUnblocksBackpressure(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	started := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Read only one byte of the body so production is already in a pipe
		// write when cancellation fires, rather than canceling before I/O.
		var first [1]byte
		if _, err := io.ReadFull(req.Body, first[:]); err != nil {
			return nil, err
		}
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	go func() {
		select {
		case <-started:
			cancel()
		case <-ctx.Done():
		}
	}()
	err := sendMultipartStream(ctx, client, streamTestRequest(ctx, "http://intake"), streamTestProducer(make([]byte, 1<<20)))
	require.ErrorIs(t, err, context.Canceled)
}

func TestMultipartStreamSlowDestinationBackpressures(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	started, release := make(chan struct{}), make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		select {
		case <-release:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		_, err := io.Copy(io.Discard, req.Body)
		return streamTestResponse(http.StatusOK), err
	})}
	done := make(chan error, 1)
	go func() {
		done <- sendMultipartStream(ctx, client, streamTestRequest(ctx, "http://intake"), streamTestProducer(make([]byte, 1<<20)))
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("upload ended before consumer started: %v", err)
	case <-ctx.Done():
		t.Fatal("consumer did not start before deadline")
	}
	select {
	case err := <-done:
		t.Fatalf("producer completed before consumer read: %v", err)
	default:
	}
	close(release)
	require.NoError(t, <-done)
}

func TestMultipartStreamRequestFailure(t *testing.T) {
	t.Parallel()
	failure := errors.New("invalid request")
	called := false
	builder := func(io.Reader, string) (*http.Request, error) { return nil, failure }
	producer := func(*multipart.Writer) error { called = true; return nil }
	require.ErrorIs(t, sendMultipartStream(t.Context(), http.DefaultClient, builder, producer), failure)
	require.False(t, called)
}
