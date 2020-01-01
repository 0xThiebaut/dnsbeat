package beater

import (
	"fmt"

	"github.com/0xThiebaut/dnsbeat/config"
	"github.com/0xThiebaut/dnsbeat/lib/collector"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

// Dnsbeat configuration.
type Dnsbeat struct {
	done   chan struct{}
	config config.Config
	client beat.Client
	logger *logp.Logger
}

// New creates an instance of dnsbeat.
func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	c := config.DefaultConfig
	if err := cfg.Unpack(&c); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	bt := &Dnsbeat{
		done:   make(chan struct{}),
		config: c,
		logger: logp.NewLogger("dnsbeat"),
	}
	return bt, nil
}

// Run starts dnsbeat.
func (bt *Dnsbeat) Run(b *beat.Beat) error {
	bt.logger.Info("dnsbeat is running! Hit CTRL-C to stop it.")
	// Connect the client
	if client, err := b.Publisher.Connect(); err != nil {
		return err
	} else {
		bt.client = client
	}
	// Start all collectors sequentially
	collectors := make([]collector.Collector, len(bt.config.Zones))
	for _, conf := range bt.config.Zones {
		c := collector.New(conf, bt.client)
		if err := c.Start(); err != nil {
			bt.logger.Errorf("An error occurred while collecting %v: %s", conf.FQDN, err.Error())
		} else {
			collectors = append(collectors, c)
		}
	}
	// Wait for a shut-down signal
	<-bt.done
	// Close all collectors
	for i, c := range collectors {
		if err := c.Close(); err != nil {
			bt.logger.Errorf("An error occurred while closing the %v collector (%d): %s", c.String(), i, err.Error())
		}
	}
	return nil
}

// Stop stops dnsbeat.
func (bt *Dnsbeat) Stop() {
	close(bt.done)
	if err := bt.client.Close(); err != nil {
		bt.logger.Errorf("An error occurred while closing the client: %s", err.Error())
	}
}
