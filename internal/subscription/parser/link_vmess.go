// SPDX-License-Identifier: GPL-3.0-only

package parser

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// V2rayNVmessOptions represents the JSON structure for v2rayn vmess format
// All fields use json.RawMessage to handle both string and number types
type V2rayNVmessOptions struct {
	V    StringOrInt `json:"v"`
	PS   string      `json:"ps"`
	Add  string      `json:"add"`
	Port StringOrInt `json:"port"`
	ID   string      `json:"id"`
	Aid  StringOrInt `json:"aid"`
	Net  string      `json:"net"`
	Type string      `json:"type"`
	Host string      `json:"host"`
	Path string      `json:"path"`
	TLS  string      `json:"tls"`
	SNI  string      `json:"sni"`
	Scy  string      `json:"scy"`
}

// StringOrInt handles JSON fields that can be either string or int
type StringOrInt int

func (s *StringOrInt) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as int first
	var intVal int
	if err := json.Unmarshal(data, &intVal); err == nil {
		*s = StringOrInt(intVal)
		return nil
	}

	// Try to unmarshal as string
	var strVal string
	if err := json.Unmarshal(data, &strVal); err == nil {
		if strVal == "" {
			*s = 0
			return nil
		}
		intVal, err := strconv.Atoi(strVal)
		if err != nil {
			return err
		}
		*s = StringOrInt(intVal)
		return nil
	}

	return E.New("cannot unmarshal value")
}

// ParseVmessLink parses vmess:// link in v2rayn format
// Supports two formats:
// 1. vmess://base64(json) - Standard v2rayn format
// 2. vmess://uuid@host:port?params - Extended URL format
func ParseVmessLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}

	// Try to parse as base64-encoded JSON first
	if linkURL.User == nil {
		return parseVmessBase64(linkURL)
	}

	// Parse as extended URL format (uuid@host:port)
	return parseVmessURL(linkURL)
}

func parseVmessBase64(linkURL *url.URL) (option.Outbound, error) {
	// linkURL.Host contains the base64-encoded data
	// v2rayn uses standard base64 encoding
	encoded := linkURL.Host + linkURL.Path
	data, err := decodeVmessBase64(encoded)
	if err != nil {
		return option.Outbound{}, E.Cause(err, "decode base64")
	}

	var vmessOpts V2rayNVmessOptions
	err = json.Unmarshal(data, &vmessOpts)
	if err != nil {
		return option.Outbound{}, E.Cause(err, "parse vmess json")
	}

	return buildVmessOutbound(vmessOpts), nil
}

// decodeVmessBase64 decodes base64 string (supports both standard and URL-safe)
func decodeVmessBase64(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)

	// Try standard base64 first
	if data, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		return data, nil
	}

	// Try standard base64 with padding
	if padded := padBase64(encoded); padded != encoded {
		if data, err := base64.StdEncoding.DecodeString(padded); err == nil {
			return data, nil
		}
	}

	// Try URL-safe base64
	if data, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
		return data, nil
	}

	return nil, E.New("failed to decode base64")
}

func padBase64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

func parseVmessURL(linkURL *url.URL) (option.Outbound, error) {
	var vmessOpts V2rayNVmessOptions

	// Parse UUID from user info
	vmessOpts.ID = linkURL.User.Username()
	vmessOpts.Add = linkURL.Hostname()

	// Parse port
	if portStr := linkURL.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return option.Outbound{}, E.Cause(err, "invalid port")
		}
		vmessOpts.Port = StringOrInt(port)
	}

	// Parse query parameters
	query := linkURL.Query()
	vmessOpts.PS = query.Get("remarks")
	if vmessOpts.PS == "" {
		vmessOpts.PS = query.Get("ps")
	}
	if vmessOpts.PS == "" {
		vmessOpts.PS = linkURL.Fragment
	}

	vmessOpts.Aid = StringOrInt(parseIntQuery(query, "aid", 0))
	vmessOpts.Net = query.Get("net")
	if vmessOpts.Net == "" {
		vmessOpts.Net = "tcp"
	}

	vmessOpts.Type = query.Get("type")
	vmessOpts.Host = query.Get("host")
	vmessOpts.Path = query.Get("path")
	vmessOpts.TLS = query.Get("tls")
	vmessOpts.SNI = query.Get("sni")
	vmessOpts.Scy = query.Get("scy")

	return buildVmessOutbound(vmessOpts), nil
}

func buildVmessOutbound(vmessOpts V2rayNVmessOptions) option.Outbound {
	var options option.VMessOutboundOptions
	options.Server = vmessOpts.Add
	options.ServerPort = uint16(vmessOpts.Port)
	options.UUID = vmessOpts.ID
	options.AlterId = int(vmessOpts.Aid)

	// Handle TLS
	tlsEnabled := vmessOpts.TLS == "tls" || vmessOpts.TLS == "true"
	if tlsEnabled {
		options.TLS = &option.OutboundTLSOptions{
			Enabled: true,
		}
		if vmessOpts.SNI != "" {
			options.TLS.ServerName = vmessOpts.SNI
		}
	}

	// Handle transport protocol
	net := strings.ToLower(vmessOpts.Net)
	switch net {
	case "ws":
		wsOptions := option.V2RayWebsocketOptions{
			Path: vmessOpts.Path,
		}
		if vmessOpts.Host != "" {
			wsOptions.Headers = map[string]badoption.Listable[string]{
				"Host": []string{vmessOpts.Host},
			}
		}
		options.Transport = &option.V2RayTransportOptions{
			Type:             C.V2RayTransportTypeWebsocket,
			WebsocketOptions: wsOptions,
		}
	case "http", "h2":
		options.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Path: vmessOpts.Path,
				Host: badoption.Listable[string]{vmessOpts.Host},
			},
		}
	case "grpc":
		options.Transport = &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: vmessOpts.Path,
			},
		}
	case "tcp":
		// TCP with HTTP obfuscation
		if vmessOpts.Type == "http" {
			options.Transport = &option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeHTTP,
				HTTPOptions: option.V2RayHTTPOptions{
					Path: vmessOpts.Path,
					Host: badoption.Listable[string]{vmessOpts.Host},
				},
			}
		}
	}

	var outbound option.Outbound
	outbound.Type = C.TypeVMess
	outbound.Tag = vmessOpts.PS
	outbound.Options = &options
	return outbound
}

func parseIntQuery(query url.Values, key string, defaultValue int) int {
	if val := query.Get(key); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
	}
	return defaultValue
}
