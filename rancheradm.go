package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

var rancherURL, adminUser, adminPassword, adminAccessKey, adminSecretKey, adminToken string

func usage() {
	fmt.Println(
`rancheradm - a simple rancher server administration utility. requires rancher 1.2.0

Usage: rancheradm [options] command...

  rancheradm token             -- create a token
  rancheradm localauth on      -- enable local authentication using adminuser/adminpassword
  rancheradm localauth off     -- disable local authentication
  rancheradm get SETTING       -- get setting
  rancheradm set SETTING VALUE -- set setting to value
  rancheradm registration      -- list environments
  rancheradm registration ENV  -- get registration url for environment ENV

Most commands require authentication by one of admin user/password, admin access/secret key
or admin jwt token. Those and the RANCHER_URL can be set in the environment.
  
Options:
`)
	flag.PrintDefaults()
}

func main() {

	flag.StringVar(&rancherURL, "url", os.Getenv("RANCHER_URL"), "rancher url (RANCHER_URL)")
	flag.StringVar(&adminUser, "adminuser", os.Getenv("RANCHER_ADMIN_USER"), "rancher admin user (RANCHER_ADMIN_USER)")
	flag.StringVar(&adminPassword, "adminpassword", os.Getenv("RANCHER_ADMIN_PASSWORD"), "rancher admin password (RANCHER_ADMIN_PASSWORD)")
	flag.StringVar(&adminAccessKey, "adminaccesskey", os.Getenv("RANCHER_ADMIN_ACCESS_KEY"), "rancher admin access key (RANCHER_ADMIN_ACCESS_KEY)")
	flag.StringVar(&adminSecretKey, "adminsecretkey", os.Getenv("RANCHER_ADMIN_SECRET_KEY"), "rancher admin secret key (RANCHER_ADMIN_SECRET_KEY)")
	flag.StringVar(&adminToken, "admintoken", os.Getenv("RANCHER_ADMIN_TOKEN"), "rancher admin jwt token (RANCHER_ADMIN_TOKEN)")

	flag.Parse()

	if len(rancherURL) < 1 {
		panic("need rancher URL")
	}

	if len(os.Args) == 1 {
		usage()
		return
	}

	switch os.Args[1] {
	case "token":
		cmdToken()
	case "localauth":
		cmdLocalAuth(os.Args[1:])
	case "get":
		cmdGet(os.Args[1:])
	case "set":
		cmdSet(os.Args[1:])
	case "registration":
		cmdRegistration(os.Args[1:])
	default:
		usage()
	}
}

func apiCall(method, path string, body []byte, auth bool) (respBody []byte, resp *http.Response, err error) {

	var req *http.Request

	if method == "POST" && len(body) > 0 {
		req, err = http.NewRequest(method, fmt.Sprintf("%s/v2-beta/%s", rancherURL, path), bytes.NewBuffer(body))
	} else {
		req, err = http.NewRequest(method, fmt.Sprintf("%s/v2-beta/%s", rancherURL, path), nil)
	}

	if err != nil {
		panic(err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	if auth {
		if len(adminToken) > 0 {
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", adminToken))
		} else if len(adminAccessKey) > 0 && len(adminSecretKey) > 0 {
			req.SetBasicAuth(adminAccessKey, adminSecretKey)
		} else if len(adminUser) > 0 && len(adminPassword) > 0 {
			getAdminToken()
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", adminToken))
		} else {
			panic("Need one of: admin user/password, access/secret key, or jwt token")
		}
	}

	client := &http.Client{}
	resp, err = client.Do(req)

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

	body, _, err := apiCall("POST", "/token", reqJson, false)

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
	body, _, err := apiCall("GET", "/settings", nil, true)

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

func cmdToken() {
	fmt.Println(getAdminToken())
}

func cmdLocalAuth(args []string) {
	if len(args) == 1 || args[1] == "on" {
		cmdLocalAuthOn()
	} else {
		cmdLocalAuthOff()
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

	_, resp, err := apiCall("POST", "/localauthconfig", reqJson, false)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode != http.StatusCreated { // 201
		panic("could not enable local authentication")
	}

	fmt.Printf("Local authentication enabled, use %s to login", adminUser)
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

	body, resp, err := apiCall("POST", "/localauthconfig", reqJson, true)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode != http.StatusCreated { // 201
		panic(fmt.Sprintf("could not disable local authentication: %s", body))
	}

	fmt.Println("Local authentication disabled")

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

	body, resp, err := apiCall("POST", "/settings", reqJson, true)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode != http.StatusCreated { // 201
		panic(fmt.Sprintf("could not set value: %s", body))
	}
}

func cmdRegistration(args []string) {
	body, _, err := apiCall("GET", "/projects", nil, true)

	if err != nil {
		panic(err)
	}

	var f map[string]interface{}
	err = json.Unmarshal(body, &f)

	if err != nil {
		panic(err)
	}

	var id string

	if projects, ok := f["data"].([]interface{}); ok {
		for _, pMap := range projects {
			if project, ok := pMap.(map[string]interface{}); ok {
				if len(args) == 1 {
					fmt.Println(project["name"])
				} else if args[1] == project["name"] {
					id, _ = project["id"].(string)
				}
			}
		}
	}

	if len(args) == 1 {
		return
	}

	if len(id) < 1 {
		panic(fmt.Sprintf("project %s not found", args[1]))
	}

	body, _, err = apiCall("GET", "/projects/"+id+"/registrationtokens", nil, true)

	if err != nil {
		panic(err)
	}

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
			true,
		)

		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(body, &f)

		if err != nil {
			panic(err)
		}

		regId := f["id"].(string)

		body, _, err := apiCall("GET", "/projects/"+id+"/registrationtokens/"+regId, nil, true)

		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(body, &f)

		if err != nil {
			panic(err)
		}
		fmt.Println(f["registrationUrl"])

	} else {
		panic("could not parse registration tokens for project")
	}
}
