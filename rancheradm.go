package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

var rancherURL, adminUser, adminPassword, adminAccessKey, adminSecretKey, adminToken string
var waitRetry int
var debugMode bool

func usage() {
	fmt.Println(
		`rancheradm - a simple rancher server administration utility. requires rancher 1.2.0

Usage: rancheradm [options] command...

  rancheradm token              -- create admin token
  rancheradm localauth (on|off) -- check, enable or disable local authentication
                                   (enabling will use adminuser/adminpassword)
  rancheradm get SETTING        -- get setting
  rancheradm set SETTING VALUE  -- set setting to value
  rancheradm environments       -- list environments
  rancheradm registration ENV   -- get registration url for environment ENV (default: Default)
  rancheradm envapikey ENV      -- create environment api key for ENV (default: Default)
  rancheradm apikey             -- create admin api key
  
Most commands require authentication by one of admin user/password, admin access/secret key
or admin jwt token. Those and the RANCHER_URL can be set in the environment.
  
To get the registration URL for an enviroment, you need to set the api.host first, for example

  rancheradm set api.host $RANCHER_URL
  
Options:
`)
	flag.PrintDefaults()
}

func main() {

	flag.StringVar(&rancherURL, "url", os.Getenv("RANCHER_URL"), "rancher url (env RANCHER_URL)")
	flag.StringVar(&adminUser, "adminuser", os.Getenv("RANCHER_ADMIN_USER"), "rancher admin user (env RANCHER_ADMIN_USER)")
	flag.StringVar(&adminPassword, "adminpassword", os.Getenv("RANCHER_ADMIN_PASSWORD"), "rancher admin password (env RANCHER_ADMIN_PASSWORD)")
	flag.StringVar(&adminAccessKey, "adminaccesskey", os.Getenv("RANCHER_ADMIN_ACCESS_KEY"), "rancher admin access key (env RANCHER_ADMIN_ACCESS_KEY)")
	flag.StringVar(&adminSecretKey, "adminsecretkey", os.Getenv("RANCHER_ADMIN_SECRET_KEY"), "rancher admin secret key (env RANCHER_ADMIN_SECRET_KEY)")
	flag.StringVar(&adminToken, "admintoken", os.Getenv("RANCHER_ADMIN_TOKEN"), "rancher admin jwt token (env RANCHER_ADMIN_TOKEN)")
	flag.IntVar(&waitRetry, "waitretry", 0, "wait/retry until rancher is up (in seconds)")
	flag.BoolVar(&debugMode, "debug", false, "debug mode")

	flag.Parse()

	if len(rancherURL) < 1 {
		panic("need rancher URL")
	}

	args := flag.Args()

	if len(args) == 0 {
		usage()
		return
	}

	switch args[0] {
	case "token":
		cmdToken()
	case "localauth":
		cmdLocalAuth(args[0:])
	case "get":
		cmdGet(args[0:])
	case "set":
		cmdSet(args[0:])
	case "environments":
		cmdEnvironments()
	case "registration":
		cmdRegistration(args[0:])
	case "envapikey":
		cmdEnvApiKey(args[0:])
	case "apikey":
		cmdApiKey()
	default:
		usage()
	}
}

func mkRequest(method, path string, body []byte) (req *http.Request, err error) {
	if method == "POST" && len(body) > 0 {
		req, err = http.NewRequest(method, fmt.Sprintf("%s/v2-beta/%s", rancherURL, path), bytes.NewBuffer(body))
	} else {
		req, err = http.NewRequest(method, fmt.Sprintf("%s/v2-beta/%s", rancherURL, path), nil)
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	return
}

func apiCall(method, path string, body []byte) (respBody []byte, resp *http.Response, err error) {

	if debugMode {
		fmt.Printf("%s %s\n", method, path)
	}

	var req *http.Request

	until := time.Now().Add(time.Duration(waitRetry) * time.Second)

	for true {

		req, err = mkRequest(method, path, body)

		if err != nil {
			panic(err)
		}

		if debugMode {
			fmt.Println("Trying without auth")
		}

		client := &http.Client{
			Timeout: time.Duration(5 * time.Second),
		}

		// Try without authorization first (for example, when checking for localauth status)
		resp, err = client.Do(req)

		if err == nil && resp.StatusCode == http.StatusUnauthorized {

			req, err = mkRequest(method, path, body)

			if err != nil {
				panic(err)
			}

			if debugMode {
				fmt.Println("Trying with auth")
			}

			// Retry with auth
			if len(adminToken) > 0 {
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", adminToken))
			} else if len(adminAccessKey) > 0 && len(adminSecretKey) > 0 {
				req.SetBasicAuth(adminAccessKey, adminSecretKey)
			} else if len(adminUser) > 0 && len(adminPassword) > 0 {
				getAdminToken()
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", adminToken))
			} else {
				panic("authentication required, but none of: admin user/password, access/secret key, or jwt token was set")
			}
			resp, err = client.Do(req)

			if err != nil {
				panic(err)
			}
		}
		if err == nil {
			break
		}
		if waitRetry > 0 && time.Now().After(until) {
			panic("timed out")
		}
		if debugMode {
			fmt.Printf("got %s, retrying\n", err)
		}
		if waitRetry <= 0 {
			break
		}
		time.Sleep(5 * time.Second)
	}

	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	respBody, err = ioutil.ReadAll(resp.Body)

	if err != nil {
		panic(err)
	}

	return respBody, resp, err
}

func getAdminToken() string {
	if len(adminToken) > 0 {
		return adminToken
	}
	if len(adminUser) < 1 || len(adminPassword) < 1 {
		panic("need adminUser and adminPassword to create a token")
	}

	reqData := map[string]string{
		"code":         "admin:admin",
		"authProvider": "localauthconfig",
	}

	reqJson, err := json.Marshal(reqData)

	if err != nil {
		panic(err)
	}

	body, _, err := apiCall("POST", "/token", reqJson)

	if err != nil {
		panic(err)
	}

	var f map[string]interface{}
	err = json.Unmarshal(body, &f)

	if err != nil {
		panic(err)
	}

	var ok bool

	if adminToken, ok = f["jwt"].(string); ok {
		return adminToken
	} else {
		panic("could not get jwt from json")
	}

}

func getSettings() []interface{} {
	body, _, err := apiCall("GET", "/settings", nil)

	if err != nil {
		panic(err)
	}

	var f map[string]interface{}
	err = json.Unmarshal(body, &f)

	if settings, ok := f["data"].([]interface{}); ok {
		return settings
	} else {
		panic("could not parse response for /settings")
	}

}

func getEnvironment(name string, list bool) (id string, err error) {
	body, _, err := apiCall("GET", "/projects", nil)

	if err != nil {
		panic(err)
	}

	var f map[string]interface{}
	err = json.Unmarshal(body, &f)

	if projects, ok := f["data"].([]interface{}); ok {
		for _, pMap := range projects {
			if project, ok := pMap.(map[string]interface{}); ok {
				if list {
					fmt.Println(project["name"])
				} else if project["name"] == name {
					id, _ = project["id"].(string)
				}
			}
		}
	}

	return

}

func cmdToken() {
	fmt.Println(getAdminToken())
}

func cmdLocalAuth(args []string) {
	if len(args) == 2 {
		if args[1] == "on" {
			cmdLocalAuthOn()
		} else {
			cmdLocalAuthOff()
		}
	} else {
		cmdLocalAuthCheck()
	}
}

func cmdLocalAuthOn() {
	if len(adminUser) < 1 {
		panic("need adminuser")
	}

	if len(adminPassword) < 1 {
		panic("need adminpassword")
	}

	reqData := map[string]interface{}{
		"accessMode": "unrestricted",
		"name":       adminUser,
		"type":       "localAuthConfig",
		"enabled":    true,
		"password":   adminPassword,
		"username":   adminUser,
	}

	reqJson, err := json.Marshal(reqData)

	if err != nil {
		panic(err)
	}

	_, resp, err := apiCall("POST", "/localauthconfig", reqJson)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode != http.StatusCreated { // 201
		panic("could not enable local authentication")
	}

	fmt.Printf("Local authentication enabled, use %s to login\n", adminUser)
}

func cmdLocalAuthOff() {
	reqData := map[string]interface{}{
		"accessMode": "unrestricted",
		"name":       "",
		"type":       "localAuthConfig",
		"enabled":    false,
		"password":   "",
		"username":   "",
	}

	reqJson, err := json.Marshal(reqData)

	if err != nil {
		panic(err)
	}

	body, resp, err := apiCall("POST", "/localauthconfig", reqJson)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode != http.StatusCreated { // 201
		panic(fmt.Sprintf("could not disable local authentication: %s", body))
	}

	fmt.Println("Local authentication disabled")

}

func cmdLocalAuthCheck() {
	body, _, err := apiCall("GET", "/localauthconfig", nil)

	var f map[string]interface{}
	err = json.Unmarshal(body, &f)

	if err != nil {
		panic(err)
	}

	if dataArray, ok := f["data"].([]interface{}); ok {
		if data, ok := dataArray[0].(map[string]interface{}); ok {
			if authEnabled, ok := data["enabled"].(bool); ok {
				fmt.Println(authEnabled)
			}
		}
	}
}

func cmdGet(args []string) {
	settings := getSettings()

	for _, sMap := range settings {
		if setting, ok := sMap.(map[string]interface{}); ok {
			if len(args) == 1 {
				fmt.Printf("%s=%s\n", setting["name"], setting["value"])
			} else if len(args) == 2 && setting["name"] == args[1] {
				fmt.Println(setting["value"])
			}
		}
	}
}

func cmdSet(args []string) {
	if len(args) != 3 {
		panic("syntax: set PARAMETER VALUE")
	}

	reqData := map[string]string{
		"name":  args[1],
		"value": args[2],
	}

	reqJson, err := json.Marshal(reqData)

	if err != nil {
		panic(err)
	}

	body, resp, err := apiCall("POST", "/settings", reqJson)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode != http.StatusCreated { // 201
		panic(fmt.Sprintf("could not set value: %s", body))
	}
}

func cmdEnvironments() {
	getEnvironment("", true)
}

func cmdRegistration(args []string) {

	var environmentName string

	if len(args) == 1 {
		environmentName = "Default"
	} else {
		environmentName = args[1]
	}

	id, err := getEnvironment(environmentName, false)

	if len(id) < 1 {
		panic(fmt.Sprintf("environment %s not found", environmentName))
	}

	body, _, err := apiCall("GET", "/projects/"+id+"/registrationtokens", nil)

	if err != nil {
		panic(err)
	}

	var f map[string]interface{}
	err = json.Unmarshal(body, &f)

	if err != nil {
		panic(err)
	}

	if tokens, ok := f["data"].([]interface{}); ok {
		if len(tokens) > 0 {
			// we already have registration tokens, pick one that's active
			for _, tMap := range tokens {
				if token, ok := tMap.(map[string]interface{}); ok {
					if token["state"].(string) == "active" {
						fmt.Println(token["registrationUrl"])
						return
					}
				}
			}
			// if we haven't returned by now, all of our tokens are no longer active
		}
		// we need to create a registration token
		body, _, err = apiCall(
			"POST",
			"/projects/"+id+"/registrationtokens",
			[]byte(`{"type":"registrationToken"}`),
		)

		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(body, &f)

		if err != nil {
			panic(err)
		}

		regId := f["id"].(string)

		body, _, err := apiCall("GET", "/projects/"+id+"/registrationtokens/"+regId, nil)

		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(body, &f)

		if err != nil {
			panic(err)
		}

		registationUrl := f["registrationUrl"]
		if registationUrl == nil {
			fmt.Println("registration url is nil. did you set api.host?")
		} else {
			fmt.Println(registationUrl)
		}

	} else {
		panic("could not parse registration tokens for environment")
	}

}

func cmdEnvApiKey(args []string) {

	var environmentName string

	if len(args) == 1 {
		environmentName = "Default"
	} else {
		environmentName = args[1]
	}

	id, err := getEnvironment(environmentName, false)

	if err != nil {
		panic(err)
	}

	if len(id) < 1 {
		panic(fmt.Sprintf("environment %s not found", args[1]))
	}

	reqData := map[string]interface{}{
		"description": environmentName,
		"name":        environmentName,
		"accountId":   id,
	}

	reqJson, err := json.Marshal(reqData)

	if err != nil {
		panic(err)
	}

	body, _, err := apiCall("POST", "/apiKeys", reqJson)

	var f map[string]interface{}
	err = json.Unmarshal(body, &f)

	if err != nil {
		panic(err)
	}

	fmt.Printf("%s %s\n", f["publicValue"], f["secretValue"])
}

func cmdApiKey() {

	reqData := map[string]interface{}{
		"description": adminUser,
		"name":        adminPassword,
		"accountId":   "1a1", // is this a risk?
	}

	reqJson, err := json.Marshal(reqData)

	if err != nil {
		panic(err)
	}

	body, _, err := apiCall("POST", "/apiKeys", reqJson)

	var f map[string]interface{}
	err = json.Unmarshal(body, &f)

	if err != nil {
		panic(err)
	}

	fmt.Printf("%s %s\n", f["publicValue"], f["secretValue"])
}
