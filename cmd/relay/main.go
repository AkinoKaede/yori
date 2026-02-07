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

	"github.com/AkinoKaede/proxy-relay/config"
	"github.com/AkinoKaede/proxy-relay/generator"
	"github.com/AkinoKaede/proxy-relay/server"
	"github.com/AkinoKaede/proxy-relay/subscription"
	"github.com/sagernet/sing-box/log"
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

	// Setup logger
	logFactory := log.NewNOPFactory()
	logger := logFactory.NewLogger("proxy-relay")

	if err := run(logger); err != nil {
		logger.Error("fatal: ", err)
		os.Exit(1)
	}
}

func run(log log.ContextLogger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration
	log.Info("Loading configuration from ", configPath)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return E.Cause(err, "load configuration")
	}

	log.Info("Configuration loaded successfully")

	// Initialize subscription manager
	log.Info("Initializing subscription manager with ", len(cfg.Subscriptions), " sources")
	subManager, err := subscription.NewManager(ctx, log, cfg)
	if err != nil {
		return E.Cause(err, "initialize subscription manager")
	}
	defer subManager.Close()

	// Perform initial fetch
	log.Info("Fetching all subscriptions...")
	if err := subManager.FetchAll(); err != nil {
		log.Warn("Some subscriptions failed to fetch: ", err)
	}

	// Merge outbounds
	outbounds := subManager.MergeAll()
	log.Info("Merged ", len(outbounds), " outbounds from all subscriptions")

	if len(outbounds) == 0 {
		return E.New("no outbounds available, check subscription configuration")
	}

	// Generate users
	users, userMapping := generator.GenerateUsers(outbounds, "")
	log.Info("Generated ", len(users), " users")

	// Generate sing-box configuration
	boxConfig, err := generator.GenerateConfig(cfg, outbounds, users, userMapping)
	if err != nil {
		return E.Cause(err, "generate sing-box configuration")
	}

	// Start sing-box
	boxManager := generator.NewBoxManager()
	defer boxManager.Stop()

	log.Info("Starting sing-box with ", len(cfg.Hysteria2.Ports), " inbound ports")
	if err := boxManager.Start(boxConfig); err != nil {
		return E.Cause(err, "start sing-box")
	}
	log.Info("sing-box started successfully")

	// Build HTTP server state
	var sni string
	if cfg.Hysteria2.TLS.ACME != nil && len(cfg.Hysteria2.TLS.ACME.Domain) > 0 {
		sni = cfg.Hysteria2.TLS.ACME.Domain[0]
	}

	obfsType := ""
	if cfg.Hysteria2.Obfs != nil {
		obfsType = cfg.Hysteria2.Obfs.Type
	}

	serverState := &server.State{
		Users:       users,
		PublicAddr:  cfg.Hysteria2.Public.Server,
		PublicPorts: cfg.Hysteria2.Public.Ports,
		SNI:         sni,
		Obfs:        obfsType,
	}

	// Start HTTP subscription server
	httpServer := server.NewServer(ctx, log, &server.ServerConfig{
		Listen: fmt.Sprintf("%s:%d", cfg.HTTP.Listen, cfg.HTTP.Port),
	})
	httpServer.UpdateState(serverState)

	if err := httpServer.Start(); err != nil {
		return E.Cause(err, "start HTTP server")
	}
	defer httpServer.Stop()

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
				if err := reload(ctx, log, cfg, subManager, boxManager, httpServer); err != nil {
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
	subManager *subscription.Manager,
	boxManager *generator.BoxManager,
	httpServer *server.Server,
) error {
	// Fetch updated subscriptions
	if err := subManager.FetchAll(); err != nil {
		log.Warn("Some subscriptions failed to fetch: ", err)
	}

	// Merge outbounds
	outbounds := subManager.MergeAll()
	log.Info("Reloaded ", len(outbounds), " outbounds")

	if len(outbounds) == 0 {
		return E.New("no outbounds after reload")
	}

	// Generate new users
	users, userMapping := generator.GenerateUsers(outbounds, "")
	log.Info("Generated ", len(users), " users")

	// Generate new sing-box configuration
	boxConfig, err := generator.GenerateConfig(cfg, outbounds, users, userMapping)
	if err != nil {
		return E.Cause(err, "generate configuration")
	}

	// Restart sing-box
	log.Info("Restarting sing-box...")
	if err := boxManager.Stop(); err != nil {
		log.Warn("Error stopping sing-box: ", err)
	}

	if err := boxManager.Start(boxConfig); err != nil {
		return E.Cause(err, "start sing-box")
	}
	log.Info("sing-box restarted successfully")

	// Update HTTP server state
	var sni string
	if cfg.Hysteria2.TLS.ACME != nil && len(cfg.Hysteria2.TLS.ACME.Domain) > 0 {
		sni = cfg.Hysteria2.TLS.ACME.Domain[0]
	}

	obfsType := ""
	if cfg.Hysteria2.Obfs != nil {
		obfsType = cfg.Hysteria2.Obfs.Type
	}

	serverState := &server.State{
		Users:       users,
		PublicAddr:  cfg.Hysteria2.Public.Server,
		PublicPorts: cfg.Hysteria2.Public.Ports,
		SNI:         sni,
		Obfs:        obfsType,
	}
	httpServer.UpdateState(serverState)

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
