package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

func scanForClickJack(urlToGet string) bool {
	toclickJack := false
	if strings.Contains(urlToGet, "http") {
		resp, err := http.Get(urlToGet)
		if err != nil {
			panic(err)
		}
		_, toclickJack := isVulnerable(resp, false)
		return toclickJack
	}
	return toclickJack
}

func scanForXSS(urlToGet string) bool {
	_isVulnerable := false
	if strings.Contains(urlToGet, "http") {
		for _, code := range []string{"‘;alert(String.fromCharCode(88,83,83))//’;", "alert(String.fromCharCode(88,83,83))//\";", "<Script>alert('hi')</scripT>", "alert(String.fromCharCode(88,83,83))//;", "alert(String.fromCharCode(88,83,83))//–", "></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"} {
			if strings.Contains(urlToGet, "?") {
				urlToGet = strings.Split(urlToGet, "?")[0] + "?test=" + code
			} else {
				urlToGet = urlToGet + "?test=" + code
			}
			resp, err := http.Get(urlToGet)
			if err != nil {
				log.Fatal(err)
			}
			toxss, _ := isVulnerable(resp, true)
			if toxss {
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

func scanForXSSForm(urlToPost string, data []string) bool {
	values := make(map[string]string)
	_isVulnerable := false
	if strings.Contains(urlToPost, "http") {
		for _, code := range []string{"‘;alert(String.fromCharCode(88,83,83))//’;", "alert(String.fromCharCode(88,83,83))//\";", "<Script>alert('hi')</scripT>", "alert(String.fromCharCode(88,83,83))//;", "alert(String.fromCharCode(88,83,83))//–", "></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"} {
			for _, j := range data {
				values[j] = code
			}
			json_data, err := json.Marshal(values)
			if err != nil {
				log.Fatal(err)
			}
			resp, err := http.Post(urlToPost, "application/json", bytes.NewBuffer(json_data))
			if err != nil {
				log.Fatal(err)
			}
			toxss, _ := isVulnerable(resp, true)
			if toxss {
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
