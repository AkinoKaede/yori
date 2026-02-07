// SPDX-License-Identifier: GPL-3.0-only

package cachefile

import (
	"context"
	"os"
	"path/filepath"

	E "github.com/sagernet/sing/common/exceptions"
	"go.etcd.io/bbolt"
)

const bucketSubscription = "subscription"

// CacheFile manages persistent subscription cache using bbolt
type CacheFile struct {
	ctx  context.Context
	path string
	DB   *bbolt.DB
}

// New creates a new CacheFile instance
func New(ctx context.Context, path string) *CacheFile {
	return &CacheFile{
		ctx:  ctx,
		path: path,
	}
}

// Start opens the database file
func (c *CacheFile) Start() error {
	const fileMode = 0o666

	options := bbolt.Options{
		Timeout:    0,
		NoGrowSync: false,
	}

	db, err := bbolt.Open(c.path, fileMode, &options)
	if err != nil {
		return E.Cause(err, "open cache database")
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err = tx.CreateBucketIfNotExists([]byte(bucketSubscription))
		return err
	})
	if err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return E.Errors(E.Cause(err, "create buckets"), E.Cause(closeErr, "close cache database"))
		}
		return E.Cause(err, "create buckets")
	}

	c.DB = db
	return nil
}

// Close closes the database
func (c *CacheFile) Close() error {
	if c.DB == nil {
		return nil
	}
	return c.DB.Close()
}

// PreStart ensures cache directory exists
func (c *CacheFile) PreStart() error {
	if c.path == "" {
		return nil
	}
	cacheDir := filepath.Dir(c.path)
	if cacheDir != "" && cacheDir != "." {
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return E.Cause(err, "create cache directory")
		}
	}
	return nil
}

// LoadSubscription loads a cached subscription by name
func (c *CacheFile) LoadSubscription(ctx context.Context, name string) *Subscription {
	if c.DB == nil {
		return nil
	}

	var subscription Subscription
	err := c.DB.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketSubscription))
		if bucket == nil {
			return os.ErrNotExist
		}

		data := bucket.Get([]byte(name))
		if data == nil {
			return os.ErrNotExist
		}

		return subscription.UnmarshalBinary(ctx, data)
	})
	if err != nil {
		return nil
	}
	return &subscription
}

// StoreSubscription saves a subscription to cache
func (c *CacheFile) StoreSubscription(ctx context.Context, name string, subscription *Subscription) error {
	if c.DB == nil {
		return nil
	}

	return c.DB.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketSubscription))
		if bucket == nil {
			return os.ErrNotExist
		}

		data, err := subscription.MarshalBinary(ctx)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(name), data)
	})
}
