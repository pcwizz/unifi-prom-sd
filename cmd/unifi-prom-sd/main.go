package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

type config struct {
	UnifiURL      string `json:"unifi_url"`
	BlackboxURL   string `json:"blackbox_url"`
	Site          string
	Username      string
	Password      string
	ListenPort    uint `json:"listen_port"`
	InsecureHttps bool `json:"insecure_https"`
}

type device struct {
	Name  string
	Ip    string
	Type  string
	Model string
}

type promSDEntry struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

func main() {
	configPath, ok := os.LookupEnv("CONFIG_FILE")
	if !ok {
		configPath = "config.json"
	}
	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}

	if config.InsecureHttps {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		cookies, err := login(config.UnifiURL, config.Username, config.Password)
		if err != nil {
			log.Fatal(err)
		}

		devices, err := getDeviceList(cookies, config.UnifiURL, config.Site)
		if err != nil {
			log.Fatal(err)
		}

		promSd := make([]promSDEntry, len(devices))
		for i, device := range devices {
			promSd[i] = promSDEntry{
				Targets: []string{fmt.Sprintf("%s/probe?module=icmp&target=%s", config.BlackboxURL, device.Ip)},
				Labels: map[string]string{
					"ip":    device.Ip,
					"name":  device.Name,
					"type":  device.Type,
					"model": device.Model,
				},
			}
		}

		encoder := json.NewEncoder(w)
		if err := encoder.Encode(promSd); err != nil {
			log.Fatalf("encoding prometheus service discover entries: %v", err)
		}
	})

	if err := http.ListenAndServe(fmt.Sprintf(":%v", config.ListenPort), nil); err != nil {
		log.Fatalf("starting http server: %v", err)
	}
}

func loadConfig(configPath string) (*config, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("opening config file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)

	var config config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decoding config: %w", err)
	}

	return &config, nil
}

func login(url, username, password string) ([]*http.Cookie, error) {
	credentials, err := json.Marshal(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{username, password})
	if err != nil {
		return nil, fmt.Errorf("marshalling credentials: %w", err)
	}

	resp, err := http.Post(url+"/api/login", "application/json", bytes.NewReader(credentials))
	if err != nil {
		return nil, fmt.Errorf("logging in : %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		buf := bytes.NewBufferString("")
		buf.ReadFrom(resp.Body)

		return nil, fmt.Errorf("login unsuccessful %v", buf.String())
	}

	return resp.Cookies(), nil
}

func getDeviceList(cookies []*http.Cookie, url, site string) ([]*device, error) {
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/s/%s/stat/device", url, site), nil)
	if err != nil {
		return nil, fmt.Errorf("getting device list creating request: %w", err)
	}

	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("requesting device list: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non okay status code getting device list")
	}

	object := struct {
		Data []*device
	}{
		make([]*device, 0),
	}

	decoder := json.NewDecoder(response.Body)

	if err := decoder.Decode(&object); err != nil {
		return nil, fmt.Errorf("decoding device list: %w", err)
	}

	return object.Data, nil
}
