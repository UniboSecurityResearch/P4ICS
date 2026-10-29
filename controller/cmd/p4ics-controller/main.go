// p4ics-controller: optional P4Runtime controller of P4ICS switches, with a
// web GUI. See controller/README.md. Without it, the switches run with
// simple_switch and are configured by simple_switch_CLI (testbed/).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/UniboSecurityResearch/P4ICS/controller/internal/config"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/ctl"
	"github.com/UniboSecurityResearch/P4ICS/controller/internal/gui"
)

func main() {
	path := flag.String("config", "p4ics-controller.yml", "configuration file")
	check := flag.Bool("check", false, "check the configuration and exit")
	verbose := flag.Bool("v", false, "debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", *path, err)
		os.Exit(2)
	}
	c, err := ctl.New(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", *path, err)
		os.Exit(2)
	}
	var g *gui.Server
	if cfg.GUI.Listen != "" {
		if g, err = gui.New(cfg, c, log); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", *path, err)
			os.Exit(2)
		}
	}
	if *check {
		fmt.Println("configuration OK")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if g != nil {
		go func() {
			if err := g.Serve(ctx); err != nil {
				log.Error("gui", "err", err)
				stop()
			}
		}()
	}
	if err := c.Run(ctx); err != nil {
		log.Error("stopped", "err", err)
		os.Exit(1)
	}
}
