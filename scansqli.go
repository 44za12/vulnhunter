package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

func isVulnerable(resp *http.Response, toXss bool) (bool, bool) {
	var errors []string
	if !toXss {
		errors = []string{
			"you have an error in your sql syntax",
			"warning: mysql",
			"unclosed quotation mark after the character string",
			"quoted string not properly terminated",
		}
	} else {
		errors = []string{
			"‘;alert(String.fromCharCode(88,83,83))//’;",
			"alert(String.fromCharCode(88,83,83))//\";",
			"<Script>alert('hi')</scripT>",
			"alert(String.fromCharCode(88,83,83))//;",
			"alert(String.fromCharCode(88,83,83))//–",
			"></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"}
	}
	xframeopt := string(resp.Header.Get("X-Frame-Options"))
	_isVulnerableToSqliOrXss := false
	_isVulnerableToClickJacking := (len(xframeopt) < 1 || xframeopt == "ALLOW" || xframeopt == "allow" || xframeopt == "*")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	content := string(body)
	content = strings.ToLower(content)
	for _, errorStr := range errors {
		if strings.Index(content, errorStr) > 0 {
			_isVulnerableToSqliOrXss = true
			return _isVulnerableToSqliOrXss, false
		}
	}
	return _isVulnerableToSqliOrXss, _isVulnerableToClickJacking
}

func scanForSqli(urlToGet string) bool {
	_isVulnerable := false
	if strings.Contains(urlToGet, "http") {
		if strings.Contains(urlToGet, "?") {
			for _, char := range []string{"'", string('"'), "' or 1=1;–", " \" or 1=1;–", "‘ or ‘abc‘=‘abc‘;–", "‘ or ‘ ‘=‘ ‘;–", "‘ or 1=1; drop table notes; —"} {
				resp, err := http.Get(urlToGet + char)
				if err != nil {
					panic(err)
				}
				tosqli, _ := isVulnerable(resp, false)
				if tosqli {
					_isVulnerable = true
					return _isVulnerable
				} else {
					_isVulnerable = false
					return _isVulnerable
				}
			}
		}
	}
	return _isVulnerable
}

func scanForSqliForm(urlToPost string, data []string) bool {
	values := make(map[string]string)
	_isVulnerable := false
	if strings.Contains(urlToPost, "http") {
		for _, char := range []string{"'", string('"'), "' or 1=1;–", " \" or 1=1;–", "‘ or ‘abc‘=‘abc‘;–", "‘ or ‘ ‘=‘ ‘;–", "‘ or 1=1; drop table notes; —"} {
			for _, j := range data {
				values[j] = "user" + char
			}
			json_data, err := json.Marshal(values)
			if err != nil {
				log.Fatal(err)
			}
			resp, err := http.Post(urlToPost, "application/json", bytes.NewBuffer(json_data))
			if err != nil {
				log.Fatal(err)
			}
			tosqli, _ := isVulnerable(resp, false)
			if tosqli {
				_isVulnerable = true
				return _isVulnerable
			} else {
				_isVulnerable = false
				return _isVulnerable
			}
		}
	}
	return _isVulnerable
}
