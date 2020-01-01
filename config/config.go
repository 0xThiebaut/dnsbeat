// Config is put into a different package to prevent cyclic imports in case
// it is needed in several locations

package config

import "time"

type Config struct {
	Zones []ZoneConfig `config:"zones"`
}

var DefaultConfig = Config{
	Zones: []ZoneConfig{},
}

type ZoneConfig struct {
	FQDN        string             `config:"fqdn"`
	Bind        string             `config:"bind"`
	NameServers []NameServerConfig `config:"nameservers"`
	ZoneFile    string             `config:"zonefile"`
	Timeouts    *TimeoutConfig     `config:"timeouts"`
	Period      time.Duration      `config:"period"`
}

var DefaultZoneConfig = ZoneConfig{
	Period: time.Minute * 10,
}

type NameServerConfig struct {
	Hostname string      `config:"hostname"`
	TSIG     *TSIGConfig `config:"tsig"`
}

type TimeoutConfig struct {
	Dial time.Duration `config:"dial"`
	Read time.Duration `config:"read"`
}

var DefaultTimeoutConfig = TimeoutConfig{
	Dial: time.Second * 3,
	Read: time.Second * 10,
}

type TSIGConfig struct {
	Secret    string        `config:"secret"`
	Algorithm string        `config:"algorithm"`
	Fudge     time.Duration `config:"fudge"`
}

var DefaultTSIGConfig = TSIGConfig{
	Fudge: time.Minute * 5,
}
