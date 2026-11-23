// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package dentry holds dentry related files
package dentry

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/DataDog/datadog-go/v5/statsd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/security/probe/config"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

type fakePathnamesMap struct {
	entries map[model.PathKey]model.PathLeaf
}

func (m *fakePathnamesMap) Lookup(key, valueOut interface{}) error {
	var pk model.PathKey
	switch k := key.(type) {
	case model.PathKey:
		pk = k
	case []byte:
		if len(k) < model.PathKeySize {
			return errors.New("invalid key buffer")
		}
		pk.Inode = binary.NativeEndian.Uint64(k[0:8])
		pk.MountID = binary.NativeEndian.Uint32(k[8:12])
		pk.PathID = binary.NativeEndian.Uint32(k[12:16])
	default:
		return errors.New("unsupported key type")
	}

	leaf, ok := m.entries[pk]
	if !ok {
		return ErrEntryNotFound
	}
	out, ok := valueOut.(*model.PathLeaf)
	if !ok {
		return errors.New("unsupported valueOut type")
	}
	*out = leaf
	return nil
}

func TestComputeFilenameFromParts(t *testing.T) {
	type testEntry struct {
		name     string
		parts    [][]byte
		expected string
	}

	entries := []testEntry{
		{
			name:     "empty",
			parts:    [][]byte{},
			expected: "/",
		},
		{
			name: "basic",
			parts: [][]byte{
				[]byte("a"),
				[]byte("b"),
				[]byte("c"),
			},
			expected: "/c/b/a",
		},
	}

	for _, entry := range entries {
		t.Run(entry.name, func(t *testing.T) {
			assert.Equal(t, entry.expected, computeFilenameFromParts(entry.parts))
		})
	}
}

func TestHardLinkBypassesLeafCache(t *testing.T) {
	dr, err := NewResolver(&config.Config{
		DentryCacheSize:            128,
		MapDentryResolutionEnabled: true,
	}, &statsd.NoOpClient{}, nil)
	require.NoError(t, err)

	const mountID = uint32(9)
	const highPathID = uint32(0x00010000)

	leafKey := model.PathKey{Inode: 500, MountID: mountID, PathID: highPathID | 0x0003}
	parentKey := model.PathKey{Inode: 100, MountID: mountID, PathID: highPathID | 0x0003}
	rootKey := model.PathKey{Inode: 1, MountID: mountID, PathID: highPathID | 0x0003}

	// Preload stale alias A in the userspace cache under the same key.
	dr.cacheInode(leafKey, PathEntry{Parent: parentKey, Name: "alias-a"})

	var leafB model.PathLeaf
	leafB.Parent = parentKey
	leafB.SetName("alias-b")

	var parentLeaf model.PathLeaf
	parentLeaf.Parent = rootKey
	parentLeaf.SetName("dir")

	var rootLeaf model.PathLeaf
	rootLeaf.SetName("/")

	dr.pathnames = &fakePathnamesMap{
		entries: map[model.PathKey]model.PathLeaf{
			leafKey:   leafB,
			parentKey: parentLeaf,
			rootKey:   rootLeaf,
		},
	}

	// Both full-path and basename resolution with cache=false (hardlink path) must return alias B from the kernel map.
	fullPath, err := dr.Resolve(leafKey, false, CallerFileHardLink)
	require.NoError(t, err)
	assert.Equal(t, "/dir/alias-b", fullPath)

	basename := dr.ResolveName(leafKey, false, CallerFileHardLink)
	assert.Equal(t, "alias-b", basename)

	// The leaf cache entry was not overwritten by the cache=false lookups.
	cachedLeaf, err := dr.lookupInodeFromCache(leafKey)
	require.NoError(t, err)
	assert.Equal(t, "alias-a", cachedLeaf.Name)
}
