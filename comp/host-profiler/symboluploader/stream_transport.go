// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build linux

package symboluploader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
)

// sendMultipartStream produces a multipart body and sends it to one destination
// through an unbuffered pipe, so the destination paces the producer and the
// body is never buffered. request must build its request with ctx.
func sendMultipartStream(ctx context.Context, client *http.Client,
	request func(io.Reader, string) (*http.Request, error), produce func(*multipart.Writer) error,
) error {
	body, pipe := io.Pipe()
	output := &outputErrorWriter{w: pipe}
	mw := multipart.NewWriter(output)
	req, err := request(body, mw.FormDataContentType())
	if err != nil {
		return err
	}
	// Closing the reader is what unblocks a pipe write to a stalled destination.
	stop := context.AfterFunc(ctx, func() { body.CloseWithError(ctx.Err()) })
	defer stop()
	sent := make(chan error, 1)
	go func() { sent <- sendStreamRequest(client, req, body) }()
	producerErr := produce(mw)
	if producerErr == nil {
		producerErr = mw.Close()
	}
	pipe.CloseWithError(producerErr)
	uploadErr := <-sent
	if output.err != nil && uploadErr == nil {
		// The destination stopped reading early, so it did not get the whole
		// body even though it answered 2xx.
		uploadErr = fmt.Errorf("upload symbols to %s: incomplete request: %w", req.URL.Redacted(), io.ErrUnexpectedEOF)
	}
	return errors.Join(producerErr, uploadErr)
}

func sendStreamRequest(client *http.Client, req *http.Request, body *io.PipeReader) error {
	resp, err := client.Do(req)
	// Stop reading before handling the response, so an early response unblocks
	// the producer even if its body stalls.
	body.CloseWithError(err)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		diagnostic, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("upload symbols to %s: %s: %.4096s", req.URL.Redacted(), resp.Status, diagnostic)
	}
	return nil
}
