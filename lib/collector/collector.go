package collector

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/0xThiebaut/dnsbeat/config"
	"github.com/0xThiebaut/dnsbeat/lib/parser"
	"github.com/miekg/dns"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/logp"
)

type Collector interface {
	Start() error
	Close() error
	String() string
}

type collector struct {
	config             config.ZoneConfig
	logger             *logp.Logger
	client             beat.Client
	ticker             *time.Ticker
	done               chan struct{}
	mutex              sync.Mutex
	DefaultDialTimeout time.Duration
	DefaultReadTimeout time.Duration
	DefaultFudge       time.Duration
	DefaultPeriod      time.Duration
}

func New(conf config.ZoneConfig, client beat.Client) Collector {
	return &collector{
		config:             conf,
		client:             client,
		logger:             logp.NewLogger(fmt.Sprintf("collector-%s", conf.FQDN)),
		done:               make(chan struct{}),
		DefaultDialTimeout: config.DefaultTimeoutConfig.Dial,
		DefaultReadTimeout: config.DefaultTimeoutConfig.Read,
		DefaultFudge:       config.DefaultTSIGConfig.Fudge,
		DefaultPeriod:      config.DefaultZoneConfig.Period,
	}
}

func (c *collector) Start() error {
	c.logger.Infof("Collecting %v", c.config.FQDN)
	err := c.collect()
	if err != nil {
		c.logger.Debugf("An error occurred while collecting %v: %s", c.config.FQDN, err.Error())
		return err
	}
	period := c.config.Period
	if period < 0 {
		err := errors.New(fmt.Sprintf("An invalid period of %s has been configured", period.String()))
		c.logger.Debug(err.Error())
		return err
	} else if period == 0 {
		c.logger.Debugf("No period has been configured (using %s as default)", c.DefaultPeriod.String())
		period = c.DefaultPeriod
	}
	safeguard := time.Second * 10
	if period < safeguard {
		c.logger.Warnf("The configured period of %s seems extremely low and may lead to unnecessary load on the name servers (if you don't know what you are doing, consider increasing the period to %s)", period.String(), safeguard.String())
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.ticker != nil {
		err := errors.New("The collector has already been started and can't be started twice")
		c.logger.Debug(err)
		return err
	}
	c.ticker = time.NewTicker(period)
	c.logger.Infof("Next collection in %s", period.String())
	go func() {
		defer c.ticker.Stop()
		for {
			select {
			case <-c.done:
				return
			case <-c.ticker.C:
				c.logger.Infof("Collecting %v, next collection in %s", c.config.FQDN, period.String())
				if err := c.collect(); err != nil {
					c.logger.Errorf("An error occurred while collecting %v: %s", c.config.FQDN, err.Error())
				}
			}
		}
	}()
	return nil
}

func (c *collector) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.ticker == nil {
		err := errors.New("The collector is not running")
		c.logger.Debug(err.Error())
		return err
	}
	close(c.done)
	c.ticker = nil
	return nil
}

func (c *collector) String() string {
	return c.config.FQDN
}

func (c *collector) collect() error {
	for _, nameserver := range c.config.NameServers {
		if err := c.collectDns(nameserver); err != nil {
			c.logger.Warnf("An error occurred while collecting %v from %v: %s", c.config.FQDN, nameserver.Hostname, err.Error())
		} else {
			return nil
		}
	}
	// Attempt to parse the zone file
	if err := c.collectFile(); err != nil {
		c.logger.Warnf("An error occurred while collecting %v locally: %s", c.config.FQDN, err.Error())
	} else {
		return nil
	}
	err := errors.New(fmt.Sprintf("Unable to collect %v from any of the %d configured name servers and from zone file", c.config.FQDN, len(c.config.NameServers)))
	c.logger.Debug(err)
	return err
}

func (c *collector) collectDns(nameserver config.NameServerConfig) error {
	if len(nameserver.Hostname) == 0 {
		err := errors.New(fmt.Sprintf("An name server is missing its host name for %v", c.config.FQDN))
		c.logger.Debug(err.Error())
		return err
	}
	// Prepare transfer
	t, err := c.transfer(nameserver)
	if err != nil {
		err = errors.New(fmt.Sprintf("An error occurred while contacting %v for %v: %s", nameserver.Hostname, c.config.FQDN, err.Error()))
		c.logger.Debug(err.Error())
		return err
	}
	// Prepare message
	m, err := c.message(nameserver)
	if err != nil {
		err = errors.New(fmt.Sprintf("An error occurred while querying %v for %v: %s", nameserver.Hostname, c.config.FQDN, err.Error()))
		c.logger.Debug(err.Error())
		return err
	}
	// Make transfer
	envs, err := t.In(m, c.config.FQDN)
	if err != nil {
		err = errors.New(fmt.Sprintf("An error occurred while transferring %v from %v: %s", c.config.FQDN, nameserver.Hostname, err.Error()))
		c.logger.Debug(err.Error())
		return err
	}
	timestamp := time.Now().UTC()
	// Iterate through the envelopes
	for env := range envs {
		if env.Error != nil {
			c.logger.Warnf("An error occurred while retrieving an envelope from %v for %v: %s", nameserver.Hostname, c.config.FQDN, env.Error.Error())
			continue
		}
		// Iterate through resource records
		for _, rr := range env.RR {
			// Parse resource record
			parsed := parser.Parse(rr, c.config.FQDN, time.Now(), nameserver.Hostname)
			// Publish the event
			c.client.Publish(beat.Event{
				Timestamp: timestamp,
				Fields:    parsed,
			})
		}
	}
	return nil
}

func (c *collector) collectFile() error {
	if len(c.config.ZoneFile) <= 0 {
		err := errors.New(fmt.Sprintf("No zone file configured for %v", c.config.FQDN))
		c.logger.Debug(err)
		return err
	}
	stat, err := os.Stat(c.config.ZoneFile)
	if err != nil {
		err := errors.New(fmt.Sprintf("Unable to collect %v from the file %v: %s", c.config.FQDN, c.config.ZoneFile, err.Error()))
		c.logger.Debug(err)
		return err
	} else if stat.IsDir() {
		err := errors.New(fmt.Sprintf("Unable to collect %v from the file %v which is a directory", c.config.FQDN, c.config.ZoneFile))
		c.logger.Debug(err)
		return err
	}
	zonefile, err := os.Open(c.config.ZoneFile)
	if err != nil {
		err := errors.New(fmt.Sprintf("Unable to collect %v from the file %v: %s", c.config.FQDN, c.config.ZoneFile, err.Error()))
		c.logger.Debug(err)
		return err
	}
	// Close the file when done
	defer func() {
		if e := zonefile.Close(); e != nil {
			c.logger.Errorf("An error occurred while closing the zone file configured for %v at %v: %s", c.config.FQDN, c.config.ZoneFile, e.Error())
		}
	}()
	timestamp := stat.ModTime().UTC()
	// Create a zone parser
	zp := dns.NewZoneParser(zonefile, c.config.FQDN, c.config.ZoneFile)
	// Iterate through resource records
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		// Parse resource record
		parsed := parser.Parse(rr, c.config.FQDN, time.Now(), "localhost")
		// Publish the event
		c.client.Publish(beat.Event{
			Timestamp: timestamp,
			Fields:    parsed,
		})
	}
	if err = zp.Err(); err != nil {
		err := errors.New(fmt.Sprintf("An error occurred while parsing the zone file configured for %v at %v: %s", c.config.FQDN, c.config.ZoneFile, err.Error()))
		c.logger.Debug(err)
		return err
	}
	return nil
}

func (c *collector) transfer(nameserver config.NameServerConfig) (t *dns.Transfer, err error) {
	// Create dialer
	d := new(net.Dialer)
	// Set bind IP if configured
	if len(c.config.Bind) > 0 {
		ip, err := net.ResolveIPAddr("ip", c.config.Bind)
		if err != nil {
			c.logger.Debugf("An error occurred while resolving the desired %v outbound IP: %s", c.config.Bind, err.Error())
			return nil, err
		}
		c.logger.Debugf("Using the desired %v outbound IP", ip.String())
		d.LocalAddr = ip
	} else {
		c.logger.Debug("No desired outbound IP configured (the system will choose)")
	}
	// Set dial timeout if configured
	if c.config.Timeouts.Dial < 0 {
		err := errors.New(fmt.Sprintf("An invalid dial timeout of %s has been configured", c.config.Timeouts.Dial.String()))
		c.logger.Debug(err.Error())
		return nil, err
	} else if c.config.Timeouts.Dial == 0 {
		c.logger.Debugf("No dial timeout has been configured (using %s as default)", c.DefaultDialTimeout.String())
		d.Timeout = c.DefaultDialTimeout
	} else {
		c.logger.Debugf("Using the configured dial timeout of %s", c.config.Timeouts.Dial.String())
		d.Timeout = c.config.Timeouts.Dial
	}
	// Connect to the name server
	con, err := d.Dial("tcp", nameserver.Hostname)
	if err != nil {
		c.logger.Debugf("An error occurred while dialing %v: %s", nameserver.Hostname, err.Error())
		return nil, err
	}
	c.logger.Debugf("Dialed the %v name server", nameserver.Hostname)
	// Create a DNS connection
	dnscon := &dns.Conn{Conn: con}
	// Create new transfer
	t = &dns.Transfer{Conn: dnscon}
	// Set timeouts
	if c.config.Timeouts != nil {
		// Set dial timeout
		if c.config.Timeouts.Dial < 0 {
			err := errors.New(fmt.Sprintf("An invalid dial timeout of %s has been configured", c.config.Timeouts.Dial.String()))
			c.logger.Debug(err.Error())
			return nil, err
		} else if c.config.Timeouts.Dial == 0 {
			c.logger.Debugf("No dial timeout has been configured (using %s as default)", c.DefaultDialTimeout.String())
			d.Timeout = c.DefaultDialTimeout
		} else {
			c.logger.Debugf("Using the configured dial timeout of %s", c.config.Timeouts.Dial.String())
			t.DialTimeout = c.config.Timeouts.Dial
		}
		// Set read timeout
		if c.config.Timeouts.Read < 0 {
			err := errors.New(fmt.Sprintf("An invalid read timeout of %s has been configured", c.config.Timeouts.Read.String()))
			c.logger.Debug(err.Error())
			return nil, err
		} else if c.config.Timeouts.Read == 0 {
			c.logger.Debugf("No read timeout has been configured (using %s as default)", c.DefaultReadTimeout.String())
			d.Timeout = c.DefaultReadTimeout
		} else {
			c.logger.Debugf("Using the configured read timeout of %s", c.config.Timeouts.Read.String())
			t.ReadTimeout = c.config.Timeouts.Read
		}
	}
	// Set TSIG
	if nameserver.TSIG != nil && len(nameserver.TSIG.Secret) > 0 {
		c.logger.Debugf("Using the configured %v TSIG secret", nameserver.TSIG.Secret)
		t.TsigSecret = map[string]string{"axfr.": nameserver.TSIG.Secret}
	} else {
		c.logger.Debug("No TSIG secret defined (requests will be unauthenticated)")
	}
	return t, nil
}

func (c *collector) message(nameserver config.NameServerConfig) (m *dns.Msg, err error) {
	// Create message
	m = new(dns.Msg)
	m.SetAxfr(c.config.FQDN)
	// Set TSIG
	if nameserver.TSIG == nil || len(nameserver.TSIG.Secret) == 0 {
		c.logger.Debug("No TSIG secret defined (requests will be unauthenticated)")
	} else if len(nameserver.TSIG.Algorithm) == 0 {
		err := errors.New("The configured TSIG is missing its algorithm which must be one of \"hmacmd5\", \"hmacsha1\", \"hmacsha256\" or \"hmacsha512\"")
		c.logger.Debug(err.Error())
		return nil, err
	} else {
		//Strip non-alphanumerics
		reg, err := regexp.Compile("[^a-zA-Z0-9]+")
		if err != nil {
			c.logger.Debugf("An error occurred while normalizing the %v algorithm: %s", nameserver.TSIG.Algorithm, err.Error())
			return nil, err
		}
		algorithm := reg.ReplaceAllString(nameserver.TSIG.Algorithm, "")
		//To lower to increase the accepted formats
		switch strings.ToLower(algorithm) {
		case "hmacmd5":
			algorithm = dns.HmacMD5
		case "hmacsha1":
			algorithm = dns.HmacSHA1
		case "hmacsha256":
			algorithm = dns.HmacSHA256
		case "hmacsha512":
			algorithm = dns.HmacSHA512
		default:
			err := errors.New(fmt.Sprintf("The configured %v TSIG algorithm is unknown and must be one of \"hmacmd5\", \"hmacsha1\", \"hmacsha256\" or \"hmacsha512\"", nameserver.TSIG.Algorithm))
			c.logger.Debug(err.Error())
			return nil, err
		}
		// Set fudge
		fudge := nameserver.TSIG.Fudge.Seconds()
		if fudge < 0 {
			err := errors.New(fmt.Sprintf("An invalid TSIG fudge of %s has been configured", nameserver.TSIG.Fudge.String()))
			c.logger.Debug(err.Error())
			return nil, err
		} else if fudge > math.MaxInt16 {
			limit := time.Second * math.MaxInt16
			c.logger.Debugf("The configured TSIG fudge of %s exceeds the RFC 2845 limit of 16 bits and has been caped at %s", nameserver.TSIG.Fudge.String(), limit.String())
			fudge = math.MaxInt16
		} else if fudge == 0 {
			c.logger.Debugf("No TSIG fudge has been configured (using %s as default)", c.DefaultFudge.String())
			fudge = c.DefaultFudge.Seconds()
		} else {
			c.logger.Debugf("Using the configured TSIG fudge of %s", nameserver.TSIG.Fudge.String())
		}
		m.SetTsig("axfr.", algorithm, uint16(fudge), time.Now().Unix())
	}
	return m, nil
}
