# Zhi-Zhu
![GitHub Repo stars](https://img.shields.io/github/stars/captain-woof/zhi-zhu?style=for-the-badge) ![GitHub all releases](https://img.shields.io/github/downloads/captain-woof/zhi-zhu/total?style=for-the-badge)

### Introduction

**Zhi-Zhu is a multithreaded spidering script** that recursively searches base webpages and all urls appearing in it, for specific (regex) words. It spawns as many concurrent threads as you specify, then begins spidering. Each spidered webpage is not visited twice, preventing loops. Out of scope urls are logged, and can be optionally specified to also be stored in a separate file.

### Use-cases

- You want to search all pages of a website for particular phrases, like '.\*login.\*', '.\*admin.\*', etc
- You want a list of all webpages (the urls) of a website (for this, use regex ".*")

### Usage
```
usage: zhi-zhu.py [-h] [-u URLS | -f URLS_FILE] [-c COOKIE] [-H HEADER] [-o OUTPUT] [-oO OUTPUT_OUT_OF_SCOPE] [-t THREADS_MAX]
                  [--whitelist-domains WHITELIST_DOMAINS | --whitelist-domains-file WHITELIST_DOMAINS_FILE] -w WORDS_TO_SEARCH
                  [--disable-colored-output] [--timeout TIMEOUT] [--max-retries MAX_RETRIES] [--case-sensitive]
                  [--url-attribs URL_ATTRIBS] [--result-mode {urls,words,both}]

Zhi-Zhu is a multithreaded spidering script that recursively searches base webpages and all urls appearing in it, for specific
(regex) words.

optional arguments:
  -h, --help            show this help message and exit
  -u URLS, --urls URLS  Comma separted base urls to start spidering from
  -f URLS_FILE, --urls_file URLS_FILE
                        Wordlist containing newline-separated base-urls to start spidering from
  -c COOKIE, --cookie COOKIE
                        Cookie to use in requests, format: 'cookieKey;cookieValue' (separate key,value by semicolon), can be
                        used multiple times
  -H HEADER, --header HEADER
                        HTTP Header to use in requests, format: 'headerKey:headerValue' (separate key,value by colon), can be
                        used multiple times
  -o OUTPUT, --output OUTPUT
                        Output file to store results in
  -oO OUTPUT_OUT_OF_SCOPE, --output-out-of-scope OUTPUT_OUT_OF_SCOPE
                        Output file to store out-of-scope urls in; default: None
  -t THREADS_MAX, --threads-max THREADS_MAX
                        Number of max threads to use
  --whitelist-domains WHITELIST_DOMAINS
                        Comma-separated domains to whitelist; default: (sub)domains of base urls only
  --whitelist-domains-file WHITELIST_DOMAINS_FILE
                        Newline-separated domains in an input file to whitelist; default: (sub)domains of base urls only
  -w WORDS_TO_SEARCH, --words-to-search WORDS_TO_SEARCH
                        Expression to search; regex enabled; can be used multiple times
  --disable-colored-output
                        Disable colored output
  --timeout TIMEOUT     Request timeout (secs); default: 10 secs
  --max-retries MAX_RETRIES
                        Max retries; default: 2
  --case-sensitive      Case sensitive search; default: false
  --url-attribs URL_ATTRIBS
                        HTML tag attributes that contain urls, must be comma-separated; default: 'href,src'
  --result-mode {urls,words,both}
                        Sets the output mode; 'urls' is to show only discovered URLs, 'words' to show only search words that
                        matched, 'both' for showing both (default)
```


### Author

**CaptainWoof**

![Twitter Follow](https://img.shields.io/twitter/follow/realCaptainWoof?style=social)
