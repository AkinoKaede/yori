// SPDX-License-Identifier: GPL-3.0-only

package datafile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"go.etcd.io/bbolt"
	bboltErrors "go.etcd.io/bbolt/errors"
)

const bucketPassword = "password"

// DataFile manages persistent user password storage using bbolt
type DataFile struct {
	ctx  context.Context
	path string
	DB   *bbolt.DB
}

// New creates a new DataFile instance
func New(ctx context.Context, path string) *DataFile {
	return &DataFile{
		ctx:  ctx,
		path: path,
	}
}

// Start opens the database file
func (d *DataFile) Start() error {
	const fileMode = 0o666

	options := bbolt.Options{
		Timeout:    time.Second,
		NoGrowSync: false,
	}

	var (
		db  *bbolt.DB
		err error
	)
	for i := 0; i < 10; i++ {
		db, err = bbolt.Open(d.path, fileMode, &options)
		if err == nil {
			break
		}
		if errors.Is(err, bboltErrors.ErrTimeout) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return E.Cause(err, "open data database")
	}
	if err != nil {
		return E.Cause(err, "open data database (locked by another process?)")
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err = tx.CreateBucketIfNotExists([]byte(bucketPassword))
		return err
	})
	if err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return E.Errors(E.Cause(err, "create buckets"), E.Cause(closeErr, "close data database"))
		}
		return E.Cause(err, "create buckets")
	}

	d.DB = db
	return nil
}

// Close closes the database
func (d *DataFile) Close() error {
	if d.DB == nil {
		return nil
	}
	return d.DB.Close()
}

// PreStart ensures data directory exists
func (d *DataFile) PreStart() error {
	if d.path == "" {
		return nil
	}
	dataDir := filepath.Dir(d.path)
	if dataDir != "" && dataDir != "." {
		if err := os.MkdirAll(dataDir, 0o755); err != nil {
			return E.Cause(err, "create data directory")
		}
	}
	return nil
}

// LoadPassword loads a cached password by username
func (d *DataFile) LoadPassword(ctx context.Context, username string) string {
	if d.DB == nil {
		return ""
	}

	var password string
	err := d.DB.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketPassword))
		if bucket == nil {
			return os.ErrNotExist
		}

		data := bucket.Get([]byte(username))
		if data == nil {
			return os.ErrNotExist
		}

		password = string(data)
		return nil
	})
	if err != nil {
		return ""
	}
	return password
}

// StorePassword saves a password to database
func (d *DataFile) StorePassword(ctx context.Context, username string, password string) error {
	if d.DB == nil {
		return nil
	}

	return d.DB.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketPassword))
		if bucket == nil {
			return os.ErrNotExist
		}

		return bucket.Put([]byte(username), []byte(password))
	})
}
