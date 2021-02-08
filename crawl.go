package main

import (
	"strings"

	"github.com/gocolly/colly"
)

func crawlUrls(baseUrl string) (map[string]string, map[string][]string) {
	if strings.HasSuffix(baseUrl, "/") {
		baseUrl = strings.TrimSuffix(baseUrl, "/")
	}
	sitemapget := make(map[string]string)
	sitemappost := make(map[string][]string)
	var allowedDomain string
	if strings.HasPrefix(baseUrl, "http://") {
		allowedDomain = strings.Replace(baseUrl, "http://", "", 1)
		allowedDomain = strings.Split(allowedDomain, "/")[0]
	} else if strings.HasPrefix(baseUrl, "https://") {
		allowedDomain = strings.Replace(baseUrl, "https://", "", 1)
		allowedDomain = strings.Split(allowedDomain, "/")[0]
	} else {
		allowedDomain = baseUrl
	}
	c := colly.NewCollector(
		colly.AllowedDomains(allowedDomain),
	)

	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		var path string
		if !(strings.HasPrefix(link, "http") || strings.HasPrefix(link, "mailto")) {
			if strings.HasPrefix(link, "/") {
				path = baseUrl + link
			} else if !strings.HasPrefix(path, "/") {
				if !strings.HasPrefix(path, "http") {
					path = baseUrl + string("/") + link
				}
			}
		}
		path = strings.TrimSpace(path)
		if strings.Contains(path, "?") {
			sitemapget[path] = strings.SplitAfter(path, "?")[1]
		} else {
			sitemapget[path] = ""
		}
		e.Request.Visit(link)
	})
	c.OnHTML("form", func(e *colly.HTMLElement) {
		link := e.Attr("action")
		var path string
		inputTags := e.ChildAttrs("input", "name")
		if strings.HasPrefix(link, "/") {
			path = baseUrl + link
		} else if !strings.HasPrefix(path, "/") {
			if !strings.HasPrefix(path, "http") {
				path = baseUrl + string("/") + link
			}
		}
		path = strings.TrimSpace(path)
		if len(inputTags) > 0 {
			inputTags = inputTags[:len(inputTags)-1]
		}
		sitemappost[path] = inputTags
		e.Request.Visit(link)
	})

	c.Visit(baseUrl)
	return sitemapget, sitemappost
}
