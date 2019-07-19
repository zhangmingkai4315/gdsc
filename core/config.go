package core

import "errors"

// Config store the argument info
type Config struct {
	iface       string
	port        string
	protocal    string
	metricsPath string
	metricsHost string
	server      bool
}

// NewConfig create a new config and do basic validation
func NewConfig(iface string, protocal string, port string, metricsHost string, metricsPath string) (*Config, error) {
	config := &Config{
		iface:       iface,
		port:        port,
		protocal:    protocal,
		metricsHost: metricsHost,
		metricsPath: metricsPath,
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return config, nil
}

// validate the passed arguments
func (c *Config) validate() error {
	if c.iface == "" {
		return errors.New("the iface must be set")
	}
	if c.protocal != "" && c.protocal != "tcp" && c.protocal != "udp" {
		return errors.New("the protocl must be set to tcp or udp or both")
	}
	return nil
}

// GetBPFString return bpf string from config file
// more detail from http://biot.com/capstats/bpf.html
func (c *Config) GetBPFString() string {
	port := c.port
	protocol := c.protocal
	if protocol == "" {
		return "port " + port
	}
	return protocol + " and port " + port
}
