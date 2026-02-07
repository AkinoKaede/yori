// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AkinoKaede/proxy-relay/internal/config"
	"github.com/AkinoKaede/proxy-relay/internal/datafile"
	"github.com/AkinoKaede/proxy-relay/internal/engine"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const version = "1.0.0"

var (
	configPath  string
	showVersion bool
)

func init() {
	flag.StringVar(&configPath, "c", "config.yaml", "path to configuration file")
	flag.BoolVar(&showVersion, "version", false, "show version")
}

func main() {
	flag.Parse()

	if showVersion {
		fmt.Println("proxy-relay version", version)
		return
	}

	// Load configuration first to get log level
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Setup logger with configured level
	logLevel := cfg.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	logFactory, err := log.New(log.Options{
		Context: context.Background(),
		Options: option.LogOptions{
			Level:  logLevel,
			Output: "stdout",
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create logger: %v\n", err)
		os.Exit(1)
	}
	logger := logFactory.NewLogger("proxy-relay")

	if err := run(logger, cfg); err != nil {
		logger.Error("fatal: ", err)
		os.Exit(1)
	}
}

func run(log log.ContextLogger, cfg *config.Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Info("Configuration loaded successfully")

	// Initialize data file for password storage
	var dataFile *datafile.DataFile
	if cfg.DataFile != "" {
		dataFile = datafile.New(ctx, cfg.DataFile)
		if err := dataFile.PreStart(); err != nil {
			return E.Cause(err, "prepare data file")
		}
		if err := dataFile.Start(); err != nil {
			return E.Cause(err, "start data file")
		}
		defer dataFile.Close()
		log.Info("data file initialized: ", cfg.DataFile)
	}

	engineInstance := engine.New(ctx, log, cfg, dataFile)
	if err := engineInstance.Start(); err != nil {
		return E.Cause(err, "start engine")
	}
	defer engineInstance.Close()

	// Setup reload mechanism
	reloadChan := make(chan struct{}, 1)
	go setupReloadTimer(cfg.ReloadInterval.Duration(), reloadChan, log)
	go setupSignalHandler(reloadChan, log)

	// Reload handler
	go func() {
		for {
			select {
			case <-reloadChan:
				log.Info("Reloading configuration...")
				if err := reload(ctx, log, cfg, engineInstance); err != nil {
					log.Error("Reload failed: ", err)
				} else {
					log.Info("Reload completed successfully")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Info("Received shutdown signal, stopping...")

	cancel()
	return nil
}

// reload performs a configuration reload
func reload(
	ctx context.Context,
	log log.ContextLogger,
	cfg *config.Config,
	engineInstance *engine.Engine,
) error {
	log.Info("Reloading configuration from file...")
	newCfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Error("Failed to reload configuration file: ", err)
		log.Warn("Continuing with previous configuration")
		newCfg = cfg
	}

	if err := engineInstance.Reload(newCfg); err != nil {
		return E.Cause(err, "reload engine")
	}
	return nil
}

// setupReloadTimer creates a ticker for periodic reloads
func setupReloadTimer(interval time.Duration, reloadChan chan<- struct{}, log log.ContextLogger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Info("Reload timer set to ", interval)

	for range ticker.C {
		log.Debug("Reload timer triggered")
		select {
		case reloadChan <- struct{}{}:
		default:
			log.Warn("Reload already in progress, skipping")
		}
	}
}

// setupSignalHandler listens for SIGHUP to trigger manual reload
func setupSignalHandler(reloadChan chan<- struct{}, log log.ContextLogger) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	for range sigChan {
		log.Info("Received SIGHUP signal, triggering reload")
		select {
		case reloadChan <- struct{}{}:
		default:
			log.Warn("Reload already in progress, skipping")
		}
	}
}
