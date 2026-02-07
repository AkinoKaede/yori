// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/AkinoKaede/proxy-relay/internal/config"
	"github.com/AkinoKaede/proxy-relay/internal/datafile"
	"github.com/AkinoKaede/proxy-relay/internal/engine"
	"github.com/AkinoKaede/proxy-relay/pkg/constant"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

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
		printVersion()
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

func printVersion() {
	version := constant.Version
	if version == "" {
		version = "unknown"
	}
	coreVersion := constant.CoreVersion()
	if coreVersion == "" {
		coreVersion = "unknown"
	}
	fmt.Printf("proxy-relay version %s (sing-box %s)\n\n", version, coreVersion)
	fmt.Printf("Environment: %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)

	var revision string
	if info, loaded := debug.ReadBuildInfo(); loaded {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				revision = setting.Value
				break
			}
		}
	}
	if revision != "" {
		fmt.Printf("Revision: %s\n", revision)
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
		defer func() {
			if err := dataFile.Close(); err != nil {
				log.Error("close data file: ", err)
			}
		}()
		log.Info("data file initialized: ", cfg.DataFile)
	}

	engineInstance := engine.New(ctx, log, cfg, dataFile)
	if err := engineInstance.Start(); err != nil {
		return E.Cause(err, "start engine")
	}
	defer func() {
		if err := engineInstance.Close(); err != nil {
			log.Error("close engine: ", err)
		}
	}()

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
	if interval <= 0 {
		log.Info("Reload timer disabled")
		return
	}
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
