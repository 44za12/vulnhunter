package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type Row struct {
	URL                 string `json:"url"`
	Method              string `json:"method"`
	SQLiVulnerable      bool   `json:"sqlivulnerable"`
	VulnerableParams    string `json:"vulnerableparams"`
	XSSVulnerable       bool   `json:"xssvulnerable"`
	ClickJackVulnerable bool   `json:"clickjackvulnerable"`
}

type u struct {
	Url string `json:"url"`
}

func init() {
	//Check ENV variables.
	envChecks()
}

func envChecks() {
	port, portExist := os.LookupEnv("PORT")

	if !portExist || port == "" {
		log.Fatal("PORT must be set in .env and not empty")
	}
}

func getTableArray(baseUrl string) []Row {
	var allRows []Row
	sitemapget, sitemappost := crawlUrls(baseUrl)
	for i, v := range sitemapget {
		if i == "" {
			continue
		}
		_isVulnerableToSqli := scanForSqli(i)
		_isVulnerableToXSS := scanForXSS(i)
		_isVulnerableToClickJack := scanForClickJack(i)
		if !_isVulnerableToSqli {
			v = ""
		}
		row := Row{
			URL:                 i,
			Method:              "GET",
			SQLiVulnerable:      _isVulnerableToSqli,
			VulnerableParams:    v,
			XSSVulnerable:       _isVulnerableToXSS,
			ClickJackVulnerable: _isVulnerableToClickJack,
		}
		allRows = append(allRows, row)
	}
	for i, v := range sitemappost {
		if len(v) > 0 {
			_isVulnerableToSqliForm := scanForSqliForm(i, v)
			_isVulnerableToXSS := scanForXSSForm(i, v)
			_isVulnerableToClickJack := scanForClickJack(i)
			if !_isVulnerableToSqliForm {
				v = []string{}
			}
			row := Row{
				URL:                 i,
				Method:              "POST",
				SQLiVulnerable:      _isVulnerableToSqliForm,
				VulnerableParams:    strings.Join(v, ", "),
				XSSVulnerable:       _isVulnerableToXSS,
				ClickJackVulnerable: _isVulnerableToClickJack,
			}
			allRows = append(allRows, row)
		}
	}
	return allRows
}

func index(w http.ResponseWriter, r *http.Request) {
	// parsedTemplate, _ := template.ParseFiles("Template/index.html")
	switch r.Method {
	case "GET":
		http.ServeFile(w, r, "index.html")
	case "POST":
		http.ServeFile(w, r, "index.html")
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
	}
}

func api(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var url u
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(body, &url)
		if err != nil {
			panic(err)
		}
		data := getTableArray(url.Url)
		json.NewEncoder(w).Encode(data)
	default:
		fmt.Fprintf(w, "Sorry, only POST method is supported.")
	}
}

func main() {
	http.Handle("/static/", http.StripPrefix("/static", http.FileServer(http.Dir("./static"))))
	http.HandleFunc("/", index)
	http.HandleFunc("/getdata", api)
	fmt.Printf("Starting server for testing HTTP POST...\n")
	port := os.Getenv("PORT")
	log.Fatal(http.ListenAndServe(":"+port, nil))

}
