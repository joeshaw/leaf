package leaf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"
)

const (
	baseURL      = "https://icm.infinitiusa.com/NissanConnectEVProd/rest"
	apiKey       = "Z9bNvSz8NZf0J3fLhwA3U27G4HQpwMBMYPHd3B+uzeWstfRPEue8AoS/xjIz34k8"
	userAgentKey = "pZiN3BSpfjtVulW6QB52Itw6rc5YEDZXKGlKzGsTvPY="
)

var errUnauthorized = errors.New("unauthorized")

type sessionData struct {
	VIN       string
	AuthToken string
	Cookies   []*http.Cookie
}

// Session represents a connection to the Nissan API server.
type Session struct {
	Username string
	Password string
	Country  string
	Debug    bool
	Filename string
	VIN      string

	data sessionData
}

// Load reads existing session data from the state file.
func (s *Session) Load() error {
	if s.Filename == "" {
		return nil
	}

	if s.Filename[0] == '~' {
		s.Filename = os.Getenv("HOME") + s.Filename[1:]
	}

	f, err := os.Open(s.Filename)
	if err != nil {
		return err
	}
	defer f.Close()

	var sessionData sessionData
	if err := json.NewDecoder(f).Decode(&sessionData); err != nil {
		return err
	}

	if s.VIN != "" && s.VIN != sessionData.VIN {
		// VINs don't match, so discard this session data
		return nil
	}

	s.data = sessionData

	return nil
}

func (s *Session) save() error {
	if s.Filename[0] == '~' {
		s.Filename = os.Getenv("HOME") + s.Filename[1:]
	}

	f, err := os.OpenFile(s.Filename, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	if err := json.NewEncoder(f).Encode(s.data); err != nil {
		f.Close()
		os.Remove(s.Filename)
		return err
	}

	return f.Close()
}

func (s *Session) do(method, endpoint string, v interface{}) (*http.Response, error) {
	var r io.Reader
	if v != nil {
		body, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}

		r = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, baseURL+endpoint, r)
	if err != nil {
		return nil, err
	}

	req.Header.Set("API-Key", apiKey)
	req.Header.Set("User-Agent-Key", userAgentKey)

	if r != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for _, c := range s.data.Cookies {
		req.AddCookie(c)
	}

	if s.data.AuthToken != "" {
		req.Header.Set("Authorization", s.data.AuthToken)
	}

	if s.Debug {
		body, _ := httputil.DumpRequest(req, true)
		fmt.Fprintln(os.Stderr, string(body))
		fmt.Fprintln(os.Stderr)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if s.Debug {
		body, _ := httputil.DumpResponse(resp, true)
		fmt.Fprintln(os.Stderr, string(body))
		fmt.Fprintln(os.Stderr)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errUnauthorized
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, resp.Status)
	}

	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return resp, errors.New("got non-JSON response")
	}

	// Capture the response body so we can parse it twice.  Once to look
	// for errors here, and once for the real response.
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var errResp struct {
		ErrorCode    int    `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
	}

	if err := json.Unmarshal(body, &errResp); err != nil {
		return nil, err
	}

	if errResp.ErrorCode != 0 {
		return nil, fmt.Errorf("error code %d: %s", errResp.ErrorCode, errResp.ErrorMessage)
	}

	resp.Body = ioutil.NopCloser(bytes.NewReader(body))

	return resp, nil
}

func (s *Session) doRetryAuth(method, endpoint string, v interface{}) (*http.Response, error) {
	resp, err := s.do(method, endpoint, v)
	if errors.Is(err, errUnauthorized) {
		if _, _, _, err := s.Login(); err != nil {
			return nil, err
		}

		return s.do(method, endpoint, v)
	}

	return resp, err
}

// TimeRequired represents the time needed until fully charged.
type TimeRequired struct {
	HourRequiredToFull    int `json:"hourRequiredToFull"`
	MinutesRequiredToFull int `json:"minutesRequiredToFull"`
}

// IsZero checks if the charge time is 0.
func (tr TimeRequired) IsZero() bool {
	return tr.HourRequiredToFull == 0 && tr.MinutesRequiredToFull == 0
}

// String returns a human readable duration in minutes or hours and minutes.
func (tr TimeRequired) String() string {
	if tr.HourRequiredToFull > 0 {
		return fmt.Sprintf("%dh%dm", tr.HourRequiredToFull, tr.MinutesRequiredToFull)
	}
	return fmt.Sprintf("%dm", tr.MinutesRequiredToFull)
}

// ChargingStatus represents the current charging status.
type ChargingStatus string

// String converts the charging status to "yes" or "no".
func (cs ChargingStatus) String() string {
	switch cs {
	case "NO":
		return "no"
	case "YES":
		return "yes"
	default:
		return string(cs)
	}
}

// IsCharging returns true if the vehicle is charging.
func (cs ChargingStatus) IsCharging() bool {
	switch cs {
	case "YES":
		return true
	default:
		return false
	}
}

// PluginState represents whether the vehicle is plugged in (not necessarily charging).
type PluginState string

// String converts the plugin state to "connected" or "not connected".
func (ps PluginState) String() string {
	switch ps {
	case "NOT_CONNECTED":
		return "not connected"
	case "CONNECTED":
		return "connected"
	default:
		return string(ps)
	}
}

// BatteryRecords represents all known information about the vehicle's battery and charging state.
type BatteryRecords struct {
	LastUpdatedDateAndTime time.Time `json:"lastUpdatedDateAndTime"`
	BatteryStatus          struct {
		BatteryChargingStatus  ChargingStatus `json:"batteryChargingStatus"`
		BatteryCapacity        int            `json:"batteryCapacity"`
		BatteryRemainingAmount int            `json:"batteryRemainingAmount"`
		SOC                    struct {
			Value int `json:"value"`
		} `json:"soc"`
	} `json:"batteryStatus"`
	PluginState         PluginState  `json:"pluginState"`
	CruisingRangeACOn   float64      `json:"cruisingRangeAcOn"`
	CruisingRangeACOff  float64      `json:"cruisingRangeAcOff"`
	TimeRequired        TimeRequired `json:"timeRequired"`
	TimeRequired200     TimeRequired `json:"timeRequired200"`
	TimeRequired200_6kW TimeRequired `json:"timeRequired200_6kW"`
}

// TemperatureRecords represent the current interior temperature.
type TemperatureRecords struct {
	Temperature string `json:"inc_temp"`
}

// VehicleInfo reprents the model, year and appearance of the vehicle.
type VehicleInfo struct {
	VIN       string `json:"uvi"`
	ModelName string `json:"modelname"`
	ModelYear string `json:"modelyear"`
	ExtColor  string `json:"extcolor"`
	Nickname  string `json:"nickname"`
}

// Login sets up a new session with the Nissan API and retrieves the last known vehicle, battery and temperature records.
func (s *Session) Login() (*VehicleInfo, *BatteryRecords, *TemperatureRecords, error) {
	var reqBody struct {
		Authenticate struct {
			UserID   string `json:"userid"`
			Password string `json:"password"`
			Country  string `json:"country"`
			Brand    string `json:"brand-s"`
			Language string `json:"language-s"`
		} `json:"authenticate"`
	}

	reqBody.Authenticate.UserID = s.Username
	reqBody.Authenticate.Password = s.Password
	reqBody.Authenticate.Country = s.Country

	resp, err := s.do("POST", "/auth/authenticationForAAS", reqBody)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()

	var respBody struct {
		Vehicles []struct {
			VehicleInfo
			BatteryRecords     BatteryRecords     `json:"batteryRecords"`
			TemperatureRecords TemperatureRecords `json:"temperatureRecords"`
		} `json:"vehicles"`
		AuthToken    string `json:"authToken"`
		RefreshToken string `json:"refreshToken"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, nil, nil, err
	}

	if len(respBody.Vehicles) == 0 {
		return nil, nil, nil, fmt.Errorf("no vehicles found")
	}

	// If multiple VINs are found, allow the user to choose a match.
	// Otherwise default to the first one.
	idx := -1
	if s.VIN != "" {
		for i, v := range respBody.Vehicles {
			if v.VIN == s.VIN {
				idx = i
				break
			}
		}
		if idx == -1 {
			return nil, nil, nil, fmt.Errorf("no matching VIN %s found amon %d vehicles", s.VIN, len(respBody.Vehicles))
		}
	} else {
		idx = 0
	}

	vehicle := respBody.Vehicles[idx]

	s.data.VIN = vehicle.VIN
	s.data.AuthToken = respBody.AuthToken
	s.data.Cookies = resp.Cookies()

	if s.Filename != "" {
		s.save()
	}

	return &vehicle.VehicleInfo, &vehicle.BatteryRecords, &vehicle.TemperatureRecords, nil
}

// ChargingStatus returns the current battery and temperature records.
func (s *Session) ChargingStatus() (*BatteryRecords, *TemperatureRecords, error) {
	resp, err := s.doRetryAuth(
		"GET",
		fmt.Sprintf("/battery/vehicles/%s/getChargingStatusRequest", s.data.VIN),
		nil,
	)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	var respBody struct {
		BatteryRecords     BatteryRecords     `json:"batteryRecords"`
		TemperatureRecords TemperatureRecords `json:"temperatureRecords"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, nil, err
	}

	return &respBody.BatteryRecords, &respBody.TemperatureRecords, nil
}

type commonResponse struct {
	MessageDeliveryStatus string `json:"messageDeliveryStatus"`
}

func (s *Session) climateOnOff(on bool) error {
	reqBody := struct {
		ExecutionTime time.Time `json:"executionTime"`
	}{
		ExecutionTime: time.Now().UTC(),
	}

	var endpoint string
	if on {
		endpoint = fmt.Sprintf("/hvac/vehicles/%s/activateHVAC", s.data.VIN)
	} else {
		endpoint = fmt.Sprintf("/hvac/vehicles/%s/deactivateHVAC", s.data.VIN)
	}

	resp, err := s.doRetryAuth("POST", endpoint, reqBody)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var respBody commonResponse
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return err
	}

	if respBody.MessageDeliveryStatus != "Success" {
		return fmt.Errorf("unexpected status %q", respBody.MessageDeliveryStatus)
	}

	return nil
}

// ClimateOn turns on the HVAC system.
func (s *Session) ClimateOn() error {
	return s.climateOnOff(true)
}

// ClimateOff turns off the HVAC system.
func (s *Session) ClimateOff() error {
	return s.climateOnOff(false)
}

// StartCharging turns on the vehicle charger.
func (s *Session) StartCharging() error {
	resp, err := s.doRetryAuth(
		"POST",
		fmt.Sprintf("/battery/vehicles/%s/remoteChargingRequest", s.data.VIN),
		nil,
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var respBody commonResponse
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return err
	}

	if respBody.MessageDeliveryStatus != "Success" {
		return fmt.Errorf("unexpected status %q", respBody.MessageDeliveryStatus)
	}

	return nil
}

// Location represents the GPS position of the vehicle.
type Location struct {
	Latitude     string
	Longitude    string
	ReceivedDate time.Time
}

// LocateVehicle returns the current vehicle location.
func (s *Session) LocateVehicle() (*Location, error) {
	now := time.Now().UTC()
	start := now.Add(-30 * 24 * time.Hour)

	reqBody := struct {
		AcquiredDataUpperLimit string `json:"acquiredDataUpperLimit"`
		SearchPeriod           string `json:"searchPeriod"`
		ServiceName            string `json:"MyCarFinderResult"`
	}{
		AcquiredDataUpperLimit: "1",
		SearchPeriod:           start.Format("20060102") + "," + now.Format("20060102"),
		ServiceName:            "MyCarFinderResult",
	}

	resp, err := s.doRetryAuth(
		"POST",
		fmt.Sprintf("/vehicleLocator/vehicles/%s/refreshVehicleLocator", s.data.VIN),
		reqBody,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var respBody struct {
		E struct {
			E struct {
				Body struct {
					Location struct {
						Latitude  string `json:"latitudeDMS"`
						Longitude string `json:"longitudeDMS"`
					} `json:"location"`
				} `json:"body"`
				Head struct {
					ReceivedDate time.Time `json:"receivedDate"`
				}
			} `json:"sandsNotificationEvent"`
		} `json:"sandsNotificationEvent"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, err
	}

	return &Location{
		Latitude:     respBody.E.E.Body.Location.Latitude,
		Longitude:    respBody.E.E.Body.Location.Longitude,
		ReceivedDate: respBody.E.E.Head.ReceivedDate,
	}, nil
}
