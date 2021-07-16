#!/usr/bin/python3

from colorama import init,deinit,Back,Fore
from argparse import ArgumentParser
import re
import requests
from threading import Thread, current_thread, Lock
from time import sleep
from queue import Queue, Empty
from bs4 import BeautifulSoup
from itertools import cycle

# Globals for the spidering thread
spideringStatus = {}
urls_to_spider = Queue()
whitelisted_domains = []
search_regexes = []
timeout = None
max_retries = None
urls_spidered = {}
results_found = {}
case_sensitive = None
url_attrs = None
cookies = {}
headers = {}
displayLock = Lock()
line_length = 0
exit_threads = False
out_of_scopes = []

# Function to get animated progress icon
progressIcons = cycle(['>-','->','--'])
def getProgressIcon():
    global progressIcons     
    return "[" + fg_stats + next(progressIcons) + Fore.RESET + "]"

# Function to erase previous line
def erasePreviousLine():
    global line_length
    print("\r"+" "*line_length+"\r",end="")

# Function to print line terminated by newline
def printWithNewLine(s):
    global line_length, displayLock
    with displayLock:
        erasePreviousLine()
        print(s)
        line_length = len(s)

# Function to print line without being terminated by newline
def printWithoutNewLine(s):
    global line_length, displayLock
    with displayLock:
        erasePreviousLine()
        print(s,end="")
        line_length = len(s)

# Function to get complete url from shorthand urls
def getCompleteUrl(shorthand_url,parentUrl):
    if shorthand_url.startswith("http"):
        return shorthand_url
    elif parentUrl.startswith("http"):
        return parentUrl+"/"+shorthand_url
    else:
        return "http://"+parentUrl+"/"+shorthand_url

# Function to extract domain from URL
def getDomainFromUrl(url):
    return url.split("/")[2]

# Function to add to results found
addResultLock = Lock()
def addToResultsFound(url,search_words):
    global results_found
    global addResultLock
    with addResultLock:
        results_found[url] = list(map(str.strip,search_words.copy()))

# Function to add to out of scope urls found
outOfScopeAddLock = Lock()
def addToOutOfScopeUrlsFound(url):
    global out_of_scopes
    global outOfScopeAddLock
    with outOfScopeAddLock:
        out_of_scopes.append(url)

# Function to add new url to queue
def addToSpiderQueue(url):
    global urls_spidered
    global max_retries
    global urls_to_spider

    if url in urls_spidered.keys(): # If url has already been spidered at least once
        if urls_spidered[url] < max_retries: # If url has not been spidered more than max retries            
            urls_to_spider.put(url)
    else:
        urls_to_spider.put(url)

# Function to check if url's host is whitelisted
def isUrlWithinScope(url):
    global whitelisted_domains
    domain_to_check = getDomainFromUrl(url)
    for whitelisted_domain in whitelisted_domains:
        # If url is either of a subdomain of a whitelisted domain, or the whitelisted domain itself
        if re.match(r".*\."+whitelisted_domain,domain_to_check) or domain_to_check == whitelisted_domain:
            return True
    return False

# Function for spidering thread
def spiderThreadFunc():
    global spideringStatus, urls_to_spider, whitelisted_domains, search_regexes, urls_spidered,results_found, case_sensitive, url_attrs, cookies, headers, displayLock, result_mode, exit_threads

    while not exit_threads:
        try:
            # Set self's spidering status to true
            spideringStatus[current_thread()] = True

            # get webpage to spider, see if it needs spidering again,
            # and update number of times spidering has been attempted on it
            url_to_spider = urls_to_spider.get(block=True,timeout=1)
            if url_to_spider not in urls_spidered.keys():
                urls_spidered[url_to_spider] = 0
            elif urls_spidered[url_to_spider] >= max_retries:
                continue            
            urls_spidered[url_to_spider] += 1

            # Get the webpage
            if not isUrlWithinScope(url_to_spider): # If domain is out-of-scope
                addToOutOfScopeUrlsFound(url_to_spider)
                printWithNewLine(fg_failure + "OUT OF SCOPE: {}".format(url_to_spider))
                continue
            resp = requests.get(url=url_to_spider,allow_redirects=True,timeout=timeout,cookies=cookies,headers=headers,verify=False)
            souped_response = BeautifulSoup(resp.text,'html.parser')

            # Get new urls from the webpage if any
            for tag in souped_response.find_all():                
                for attr in url_attrs:
                    try:                        
                        addToSpiderQueue(getCompleteUrl(tag.attrs[attr],getDomainFromUrl(resp.url)))
                    except KeyError:
                        pass

            # Perform the search
            search_words_results = []
            for search_regex in search_regexes:
                if case_sensitive:
                    search_words_results += re.findall(search_regex,resp.text)
                else:
                    search_words_results += re.findall(search_regex,resp.text,flags=re.IGNORECASE)
            
            # If any search words are found
            if len(search_words_results) != 0:
                # Add search results
                addToResultsFound(url_to_spider,search_words_results)

                # Display results found
                if result_mode == 'both':
                    printWithNewLine("["+fg_success+">"+fg_reset+"] "+fg_success+url_to_spider+fg_reset+" -> "+fg_info+str(search_words_results))
                elif result_mode == 'urls':
                    printWithNewLine("["+fg_success+">"+fg_reset+"] "+fg_success+url_to_spider)
                elif result_mode == 'words':
                    printWithNewLine("["+fg_success+">"+fg_reset+"] "+fg_info+str(search_words_results))                    

            # Set self's spidering status to false
            spideringStatus[current_thread()] = False
        except Empty:
            # Set self's spidering status to false
            spideringStatus[current_thread()] = False

            # Check if any other spidering threads is working,
            # which would mean that there's a possibility of new
            # webpages to work on            
            if list(spideringStatus.values()).count(True) == 0: # If no other threads are working
                exit_threads = True
                break
        except requests.exceptions.Timeout:            
            addToSpiderQueue(url_to_spider)
        except requests.exceptions.ConnectionError:
            addToSpiderQueue(url_to_spider)

# Thread function to keep displaying stats
def displayStatThreadFunc():
    global results_found, urls_spidered, urls_to_spider, spideringStatus, output, result_mode, displayLock, exit_threads
    while any(spideringStatus.values()) and not exit_threads: # While at least one spidering thread is running
        # Display stats : Last url spidered, URLs spidered, URLs remaining  
        printWithoutNewLine(getProgressIcon() + " Spidered: {} | Remaining: {}".format(len(urls_spidered),urls_to_spider.qsize()))
        # Sleep before refresing stats
        sleep(0.5)
    

# Get arguments
base_parser = ArgumentParser(epilog="Written by CaptainWoof // @realCaptainWoof",description="Zhi-Zhu is a multithreaded spidering script that recursively searches base webpages and all urls appearing in it, for specific (regex) words.")

url_mode_group = base_parser.add_mutually_exclusive_group()
url_mode_group.add_argument("-u","--urls",action='store',type=str,help='Comma separted base urls to start spidering from')
url_mode_group.add_argument("-f","--urls_file",action='store',type=str,help='Wordlist containing newline-separated base-urls to start spidering from')

base_parser.add_argument("-c","--cookie",required=False,type=str,action='append',help="Cookie to use in requests, format: 'cookieKey;cookieValue' (separate key,value by semicolon), can be used multiple times")
base_parser.add_argument("-H","--header",required=False,type=str,action='append',help="HTTP Header to use in requests, format: 'headerKey:headerValue' (separate key,value by colon), can be used multiple times")
base_parser.add_argument("-o","--output",required=False,type=str,action='store',help="Output file to store results in")
base_parser.add_argument("-oO","--output-out-of-scope",required=False,type=str,action='store',default=None,help="Output file to store out-of-scope urls in; default: None")
base_parser.add_argument("-t","--threads-max",default=10,type=int,required=False,action='store',help="Number of max threads to use")

whitelist_domain_mode = base_parser.add_mutually_exclusive_group()
whitelist_domain_mode.add_argument("--whitelist-domains",required=False,type=str,action='store',help='Comma-separated domains to whitelist; default: (sub)domains of base urls only')
whitelist_domain_mode.add_argument("--whitelist-domains-file",required=False,type=str,action='store',help='Newline-separated domains in an input file to whitelist; default: (sub)domains of base urls only')

base_parser.add_argument("-w","--words-to-search",type=str,required=True,action='append',help="Expression to search; regex enabled; can be used multiple times")
base_parser.add_argument("--disable-colored-output",required=False,default=False,action='store_true',help="Disable colored output")
base_parser.add_argument("--timeout",required=False,default=10,type=int,action='store',help="Request timeout (secs); default: 10 secs")
base_parser.add_argument("--max-retries",required=False,default=2,type=int,action='store',help="Max retries; default: 2")
base_parser.add_argument("--case-sensitive",required=False,action='store_true',default=False,help="Case sensitive search; default: false")
base_parser.add_argument("--url-attribs",required=False,default="href,src,action",type=str,action='store',help="HTML tag attributes that contain urls, must be comma-separated; default: 'href,src,action'")

result_mode = base_parser.add_argument("--result-mode",type=str,required=False,action='store',default='both',choices=['urls','words','both'],help="Sets the output mode; 'urls' is to show only discovered URLs, 'words' to show only search words that matched, 'both' for showing both (default)")

args = base_parser.parse_args()

# Get base urls
base_urls = []
if args.urls is not None:
    base_urls = [base_url for base_url in args.urls.split(",")]
else:
    for base_url in open(args.urls_file,'r'):
        base_urls.append(base_url.rstrip())

# Get domains to whitelist
if args.whitelist_domains is not None:
    whitelisted_domains = [whitelisted_domain for whitelisted_domain in args.whitelist_domains.split(",")]
elif args.whitelist_domains_file is not None:
    for whitelisted_domain in open(args.whitelist_domains_file,'r'):
        whitelisted_domains.append(whitelisted_domain.rstrip())
else:
    for base_url in base_urls:
        whitelisted_domains.append(getDomainFromUrl(base_url))

# Get search regex
search_regexes = args.words_to_search

# Get other args
max_threads = args.threads_max
output = args.output
output_out_of_scope = args.output_out_of_scope
timeout = args.timeout
max_retries = args.max_retries
case_sensitive = args.case_sensitive
url_attrs = [attributes for attributes in args.url_attribs.split(",")]
result_mode = args.result_mode

if args.cookie is not None:
    for cookieKV in args.cookie:
        cookies[cookieKV.split(";")[0]] = cookieKV.split(";")[1]
if args.header is not None:
    for headerKV in args.header:
        headers[headerKV.split(":")[0]] = headerKV.split(":")[1]

bg_success,bg_failure,fg_success,fg_failure,bg_info,fg_info,bg_reset,fg_reset,fg_stats = "","","","","","","","",""    
if not args.disable_colored_output:
    bg_success,bg_failure,fg_success,fg_failure,bg_info,fg_info,bg_reset,fg_reset,fg_stats = Back.BLUE,Back.RED,Fore.BLUE,Fore.RED,Back.MAGENTA,Fore.LIGHTMAGENTA_EX,Back.RESET,Fore.RESET,Fore.YELLOW

# Init for colorama
init(autoreset=True)

# Print search options set, and wait for 3 secs
print("OPTIONS SET\n"+"-"*11)

print(bg_info + "{:>19}".format("Base URLS"),end=": ")
for base_url in base_urls:
    print(base_url,end=",")

print("\n" + bg_info + "Whitelisted domains",end=": ")
for whitelisted_domain in whitelisted_domains:
    print(whitelisted_domain,end=",")

print("\n" + bg_info + "Search words chosen",end=": ")
for search_regex in search_regexes:
    print(search_regex,end=",")

print("\n" + bg_info + "{:>19}".format("Timeout") + bg_reset + ": {} secs".format(timeout))

if len(cookies) != 0:
    print(bg_info + "{:>19}".format("Cookies") + bg_reset + ": " + str(cookies))

if len(headers) != 0:
    print(bg_info + "{:>19}".format("Headers") + bg_reset + ": " + str(headers))

if output is not None:
    print(bg_info + "{:>19}".format("Results output") + bg_reset + ": " + output)

if output_out_of_scope is not None:
    print(bg_info + "{:>19}".format("Out-of-scope urls output") + bg_reset + ": " + output_out_of_scope)

try:
    for _ in range(1,6):
        print("..{}".format(_),end="")
        if _ != 5:
            sleep(1)
except KeyboardInterrupt:
    print("\n" + bg_failure + "Stopped!")
    deinit()
    exit()

# Init for spidering
for base_url in base_urls:
    addToSpiderQueue(base_url)

# Start spidering threads
for _ in range(max_threads):
    thread = Thread(target=spiderThreadFunc)
    spideringStatus[thread] = False
    thread.start()

# Start display thread
displayThread = Thread(target=displayStatThreadFunc)
displayThread.start()

# Stop spidering
try:
    for thread in spideringStatus.keys():
        thread.join()
except KeyboardInterrupt:
    exit_threads = True
    printWithNewLine(bg_failure + "\nInterrupting running threads, please wait...")
    for thread in spideringStatus.keys():
        thread.join()

# Stop display thread
displayThread.join()
print(bg_success + "\nSpidering finished!\n")

# Output to file if needed
if output is not None:
    with open(output,'w+') as f:
        if result_mode == 'both':
            for url,search_words_list in results_found.items():
                f.write("{} -> {}\n".format(url,search_words_list))
        elif result_mode == 'urls':
            for url in results_found.keys():
                f.write("{}\n".format(url))
        elif result_mode == 'words':
            for search_words_list in results_found.values():
                f.write("{}\n".format(search_words_list))
    print(bg_info + "Results saved to '{}'".format(output))

# Output file for out of scope urls if needed
if output_out_of_scope is not None:
    with open(output_out_of_scope,'w+') as o:
        for out_of_scope_url in out_of_scopes:
            o.write(out_of_scope_url + "\n")
    print(bg_info + "Out-of-scope urls saved to '{}'".format(output_out_of_scope))

# Deinit for colorama
deinit()
