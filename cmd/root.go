package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/Vergelab/XrayR/panel"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use: "XrayR",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(); err != nil {
				log.Fatal(err)
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file for XrayR.")
}

func getConfig() *viper.Viper {
	config := viper.New()

	// Set custom path and name
	if cfgFile != "" {
		configName := path.Base(cfgFile)
		configFileExt := path.Ext(cfgFile)
		configNameOnly := strings.TrimSuffix(configName, configFileExt)
		configPath := path.Dir(cfgFile)
		config.SetConfigName(configNameOnly)
		config.SetConfigType(strings.TrimPrefix(configFileExt, "."))
		config.AddConfigPath(configPath)
		// Set ASSET Path and Config Path for XrayR
		os.Setenv("XRAY_LOCATION_ASSET", configPath)
		os.Setenv("XRAY_LOCATION_CONFIG", configPath)
	} else {
		// Set default config path
		config.SetConfigName("config")
		config.SetConfigType("yml")
		config.AddConfigPath(".")

	}

	if err := config.ReadInConfig(); err != nil {
		log.Panicf("Config file error: %s \n", err)
	}

	config.WatchConfig() // Watch the config

	return config
}

func run() error {
	showVersion()

	config := getConfig()
	panelConfig := &panel.Config{}
	if err := config.Unmarshal(panelConfig); err != nil {
		return fmt.Errorf("parse config file %v failed: %s", cfgFile, err)
	}

	if panelConfig.LogConfig != nil && panelConfig.LogConfig.Level == "debug" {
		log.SetReportCaller(true)
	}
	if err := panelConfig.Validate(); err != nil {
		return fmt.Errorf("invalid config file %v: %s", cfgFile, err)
	}

	p := panel.New(panelConfig)
	lastTime := time.Now()
	var reloadMu sync.Mutex
	config.OnConfigChange(func(e fsnotify.Event) {
		// Discarding event received within a short period of time after receiving an event.
		if !time.Now().After(lastTime.Add(3 * time.Second)) {
			return
		}
		reloadMu.Lock()
		defer reloadMu.Unlock()
		next := &panel.Config{}
		if err := config.Unmarshal(next); err != nil {
			log.Errorf("hot reload ignored, config parse failed: %s", err)
			return
		}
		if err := next.Validate(); err != nil {
			log.Errorf("hot reload ignored, config invalid: %s", err)
			return
		}
		log.Printf("Config file changed: %s", e.Name)
		previous := panelConfig
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					log.Errorf("hot reload failed (%v); restoring the previous config", recovered)
					panelConfig = previous
					restored := panel.New(previous)
					func() {
						defer func() {
							if again := recover(); again != nil {
								log.Errorf("restore after hot reload failed: %v", again)
							}
						}()
						restored.Start()
						p = restored
					}()
				}
			}()
			p.Close()
			runtime.GC()
			panelConfig = next
			if panelConfig.LogConfig != nil && panelConfig.LogConfig.Level == "debug" {
				log.SetReportCaller(true)
			}
			p = panel.New(panelConfig)
			p.Start()
			lastTime = time.Now()
		}()
	})

	p.Start()
	defer p.Close()

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()
	// Running backend. SIGKILL cannot be caught, so it is not registered.
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	<-osSignals

	return nil
}

func Execute() error {
	return rootCmd.Execute()
}
