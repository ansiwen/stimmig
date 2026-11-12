package api

import (
	"context"
	"encoding/hex"

	"github.com/ansiwen/stimmig/canon"
	"github.com/ansiwen/stimmig/merkle"
	"github.com/ansiwen/stimmig/publog"
)

// ElectionPath returns the path prefix of an election in every service.
func ElectionPath(id merkle.Hash) string {
	return "/v1/elections/" + hex.EncodeToString(id[:])
}

// AppendRecords appends records to the log of an election through the log
// service. The log must have exactly expectSize entries before.
func AppendRecords(ctx context.Context, log *Client, id merkle.Hash, expectSize uint64, records []publog.Record) (publog.TreeHead, error) {
	req := Append{ExpectSize: &expectSize}
	for _, r := range records {
		data, err := publog.EncodeEntry(r.Type, r.Body)
		if err != nil {
			return publog.TreeHead{}, err
		}
		req.Entries = append(req.Entries, canon.Raw(data))
	}
	var head publog.TreeHead
	err := log.Do(ctx, "POST", ElectionPath(id)+"/entries", req, &head)
	return head, err
}

// Export fetches the complete log of an election from the log service.
func Export(ctx context.Context, log *Client, id merkle.Hash) ([]byte, error) {
	return log.Raw(ctx, "GET", ElectionPath(id)+"/export", nil)
}
