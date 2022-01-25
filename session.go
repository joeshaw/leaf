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
	apiKey       = "bJG8LvpcRAAOrVQ8GByIzWkR4n993iccFtKNs1sn+gheOFGnT6ABaR6cvclCXetW"
	userAgentKey = "zoJ0paOf/bCLNirsZBPQuoqtLr+OzJFdNOhLo0hrjkM="
)

var errUnauthorized = errors.New("unauthorized")

type sessionData struct {
	VehicleInfo VehicleInfo
	AuthToken   string
	Cookies     []*http.Cookie
}

// Session represents a connection to the Nissan API server.
type Session struct {
	Username string
	Password string
	Country  string
	Debug    bool
	Filename string
	VIN      string
	PIN      string

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

	// Discard old session data if it doesn't include vehcicle info.
	if sessionData.VehicleInfo.VIN == "" {
		return nil
	}

	if s.VIN != "" && s.VIN != sessionData.VehicleInfo.VIN {
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
			return nil, nil, nil, fmt.Errorf("no matching VIN %s found among %d vehicles", s.VIN, len(respBody.Vehicles))
		}
	} else {
		idx = 0
	}

	vehicle := respBody.Vehicles[idx]

	s.data.VehicleInfo = vehicle.VehicleInfo
	s.data.AuthToken = respBody.AuthToken
	s.data.Cookies = resp.Cookies()

	if s.Filename != "" {
		s.save()
	}

	return &vehicle.VehicleInfo, &vehicle.BatteryRecords, &vehicle.TemperatureRecords, nil
}

func (s *Session) VehicleInfo() *VehicleInfo {
	return &s.data.VehicleInfo
}

// ChargingStatus returns the current battery and temperature records.
func (s *Session) ChargingStatus() (*BatteryRecords, *TemperatureRecords, error) {
	resp, err := s.doRetryAuth(
		"GET",
		fmt.Sprintf("/battery/vehicles/%s/getChargingStatusRequest", s.VehicleInfo().VIN),
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
		endpoint = fmt.Sprintf("/hvac/vehicles/%s/activateHVAC", s.VehicleInfo().VIN)
	} else {
		endpoint = fmt.Sprintf("/hvac/vehicles/%s/deactivateHVAC", s.VehicleInfo().VIN)
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
		fmt.Sprintf("/battery/vehicles/%s/remoteChargingRequest", s.VehicleInfo().VIN),
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
		fmt.Sprintf("/vehicleLocator/vehicles/%s/refreshVehicleLocator", s.VehicleInfo().VIN),
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

// There is an alternate API for non-EV tasks like locking/unlocking the
// doors, flashing the lights and honking the horn.
type telematicsLogin struct {
	AccessToken string `json:"access_token"`
	AccountID   string `json:"account_id"`
	CVAPIKey    string `json:"CVApiKey"`
}

func (s *Session) telematicsLogin() (*telematicsLogin, error) {
	body := fmt.Sprintf(
		`{"username": "NISNNAVCS/%s", "password": "%s"}`,
		s.Username, s.Password,
	)

	req, err := http.NewRequest(
		"POST",
		"https://mobile.telematics.net/login/token",
		strings.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CV-APPID", "cv.nissan.connect.us.android.25")

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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, resp.Status)
	}

	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return nil, errors.New("got non-JSON response")
	}

	var respBody telematicsLogin
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, err
	}

	return &respBody, nil
}

func (s *Session) telematicsRequest(t *telematicsLogin, endpoint, command string) (string, error) {
	url := fmt.Sprintf(
		"https://prd.api.telematics.net/m/remote/accounts/niscust:nis:%s/vehicles/%s/%s",
		t.AccountID, s.VehicleInfo().VIN, endpoint,
	)
	body := fmt.Sprintf(
		`{"command":"%s", "pin":"%s"}`,
		command, s.PIN,
	)

	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.AccessToken))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CV-ApiKey", t.CVAPIKey)
	req.Header.Set("CV-AppType", "MOBILE")

	if s.Debug {
		body, _ := httputil.DumpRequest(req, true)
		fmt.Fprintln(os.Stderr, string(body))
		fmt.Fprintln(os.Stderr)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if s.Debug {
		body, _ := httputil.DumpResponse(resp, true)
		fmt.Fprintln(os.Stderr, string(body))
		fmt.Fprintln(os.Stderr)
	}

	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, resp.Status)
	}

	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return "", errors.New("got non-JSON response")
	}

	var respBody struct {
		ServiceRequestID string `json:"serviceRequestId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return "", err
	}

	return respBody.ServiceRequestID, nil
}

func (s *Session) getTelematicsRequestStatus(t *telematicsLogin, endpoint, command, requestID string) (string, error) {
	url := fmt.Sprintf(
		"https://prd.api.telematics.net/m/remote/accounts/niscust:nis:%s/vehicles/%s/%s/%s?serviceType=%s",
		t.AccountID, s.VehicleInfo().VIN, endpoint, requestID, command,
	)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.AccessToken))
	req.Header.Set("CV-ApiKey", t.CVAPIKey)
	req.Header.Set("CV-AppType", "MOBILE")

	if s.Debug {
		body, _ := httputil.DumpRequest(req, true)
		fmt.Fprintln(os.Stderr, string(body))
		fmt.Fprintln(os.Stderr)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if s.Debug {
		body, _ := httputil.DumpResponse(resp, true)
		fmt.Fprintln(os.Stderr, string(body))
		fmt.Fprintln(os.Stderr)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, resp.Status)
	}

	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		return "", errors.New("got non-JSON response")
	}

	var respBody struct {
		Status               string `json:"status"`
		ServiceType          string `json:"serviceType"`
		ServiceRequestID     string `json:"serviceRequestId"`
		ActivationDateTime   string `json:"activationDateTime"`
		StatusChangeDateTime string `json:"statusChangeDateTime"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return "", err
	}

	return respBody.Status, nil
}

func (s *Session) waitForTelematicsRequest(t *telematicsLogin, endpoint, command, requestID string, timeout time.Duration) error {
	cutoff := time.Now().Add(timeout)
	for {
		if time.Now().After(cutoff) {
			return errors.New("timed out waiting for door lock")
		}

		status, err := s.getTelematicsRequestStatus(t, "remote-door", "LOCK", requestID)
		if err != nil {
			return err
		}

		if status == "SUCCESS" {
			return nil
		}

		time.Sleep(2 * time.Second)
	}
}

// LockDoors locks the vehicle doors.
func (s *Session) LockDoors() error {
	t, err := s.telematicsLogin()
	if err != nil {
		return err
	}

	requestID, err := s.telematicsRequest(t, "remote-door", "LOCK")
	if err != nil {
		return err
	}

	return s.waitForTelematicsRequest(t, "remote-door", "LOCK", requestID, time.Minute)
}

// UnlockDoors unlocks the vehicle doors.
func (s *Session) UnlockDoors() error {
	t, err := s.telematicsLogin()
	if err != nil {
		return err
	}

	requestID, err := s.telematicsRequest(t, "remote-door", "UNLOCK")
	if err != nil {
		return err
	}

	return s.waitForTelematicsRequest(t, "remote-door", "UNLOCK", requestID, time.Minute)
}

// FlashLights flashes the vehicle lights.
func (s *Session) FlashLights() error {
	t, err := s.telematicsLogin()
	if err != nil {
		return err
	}

	requestID, err := s.telematicsRequest(t, "remote-horn-and-lights", "LIGHT_ONLY")
	if err != nil {
		return err
	}

	return s.waitForTelematicsRequest(t, "remote-horn-and-lights", "LIGHT_ONLY", requestID, time.Minute)
}

// Honk honks the vehicle horn and flashes the lights.
func (s *Session) Honk() error {
	t, err := s.telematicsLogin()
	if err != nil {
		return err
	}

	requestID, err := s.telematicsRequest(t, "remote-horn-and-lights", "HORN_LIGHT")
	if err != nil {
		return err
	}

	return s.waitForTelematicsRequest(t, "remote-horn-and-lights", "HORN_LIGHT", requestID, time.Minute)
}
