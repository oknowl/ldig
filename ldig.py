#!/usr/bin/env python3
# Link Digger - ldig.py
# Copyright (C) 2022 oknowl

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import trafilatura, sys, os, requests, re, json, unicodedata, asyncio, nest_asyncio, html, hashlib, pdfkit, argparse
import pathpy as pp
import xml.etree.cElementTree as ET
from csv import writer as csvwriter
from urllib.parse import urlparse
from dateutil.parser import parse
from dateparser.search import search_dates
from bs4 import BeautifulSoup
from statistics import median
import pandas as pd

import spacy
from spacy import displacy
try:
    nlp = spacy.load('en_core_web_lg')
except OSError:
    spacy.cli.download('en_core_web_lg')
    nlp = spacy.load('en_core_web_lg')

try:
    from conf.conf import *
except ModuleNotFoundError:
    print('[-] - No config file found, loading default values')
    archive_path = 'ldig_data/archive/'
    pdf_path = 'OUTPUT/PDFs/'
    graph_path = 'OUTPUT/graph/'
    exclusion_list = ['facebook', 'youtube', 'wikipedia','reddit', 'login', 'register']

# =========================================================================================================================================================
# logging
import logging
from pprint import pformat
LOGGER = logging.getLogger('[+]')

def LOG_DEBUG(msg):
    if isinstance(msg, str):
        LOGGER.debug("\t\t" + msg + "...")
    else:
        LOGGER.debug("\t\t" + json.dumps(msg, indent=4) + "...")
def LOG_INFO(msg):
    if isinstance(msg, str):
        LOGGER.info("\t\t" + msg + "...")
    else:
        LOGGER.info("\t\t" + json.dumps(msg, indent=4) + "...")
def LOG(msg):
    LOG_INFO(msg)
def ENABLE_LOGS():
    LOGGER.setLevel(logging.INFO)
    loggers=[(name) for name in logging.root.manager.loggerDict if name.startswith("trafilatura")]
    for i in loggers:
        logging.getLogger(i).setLevel(logging.WARNING) 
def ENABLE_DEBUG():
    LOGGER.setLevel(logging.DEBUG)
    loggers=[(name) for name in logging.root.manager.loggerDict if name.startswith("trafilatura")]
    for i in loggers:
        logging.getLogger(i).setLevel(logging.INFO) 
def DISABLE_LOGS():
    LOGGER.setLevel(logging.CRITICAL)
    loggers=[(name) for name in logging.root.manager.loggerDict if name.startswith("trafilatura")]
    for i in loggers:
        logging.getLogger(i).setLevel(logging.CRITICAL)

LOG_DEBUG("Python version")
LOG_DEBUG(sys.version)
LOG_DEBUG("Version info.")
LOG_DEBUG(sys.version_info)
# =========================================================================================================================================================
# download URL and parse for data to db
def get_all_contents(url, db):
    # reset
    downloaded = None
    # check if content already present, otherwise scrape it
    check_dirs()
    if os.path.isfile(archive_path + helper_hash(url)) and not args.force:
        LOG("Loading saved asset")
        downloaded = read_file(archive_path + helper_hash(url))
    else:
        if url.startswith("https://twitter.com"):
            LOG('Skipping twitter link')
            #LOG("Using headless chrome browser for: " + url)
            # downloaded = helper_fetch_html_chrome_headless(url)
            pass
        else:
            LOG("Downloading: " + url)
            downloaded = helper_fetch_html(url)

    # save contents
    if not os.path.isfile(archive_path + helper_hash(url)):
        if len(downloaded) > 100:
            LOG('saving new asset')
            save_file(archive_path + helper_hash(url), downloaded)

    # seed db
    # [source] 0:set(found_links), 1:title, 2:text, 3:description, 4:date, 5:set(CVEs), 6:int(similarity to 1 link), 7:NLP_seintiment, 8: suggested_queries..
    # 9: set:title-keywords, 10: set:desc-keywords, 11: set:text-keywords
    db[url] = [set(), '', '', '', '', set(), -1.0, [], set(), set(), set(), set()]
    if len(downloaded) > 100:
        LOG("Start processing content (len: " + str(len(downloaded)) + ") " + url)

        # METADATA parsing
        db = helper_parsing_meta(url, downloaded, db)
        
        # LINKS parsing
        found_links = helper_parsing_links(downloaded, url)
        
        # merge new links into db
        if found_links:
            for i in found_links:
                db[url][0].add(i['href'].strip())

        LOG("Parsing done")
        return(db)
    else:
        LOG('[-] - Could not download/read link contents. 404')
        return(db)

# fill db with extracted components
def helper_parsing_meta(url, downloaded, db):
    LOG_DEBUG("Helper parsing: Start parsing for metadata: " + url)
    # TITLE EXTRACTION
    bare = trafilatura.bare_extraction(downloaded, include_comments=False, include_links=False, output_format='python')
    if bare['title']:
        LOG_DEBUG("found title:\t" + bare['title'])  # DEBUG OUTPUT
        title = bare['title']
        db[url][1] = title

    # TEXT EXTRACTION
    if bare["text"]:
        main_body = bare["text"].replace('\n'," ")
        db[url][2] = main_body
    else:
        LOG('[-] - REMOVING link from db because NO TEXT could be extracted. Reference will prevail.')
        db.pop(url)
        LOG('[] - Removed :' + url)

    # DESCRIPTION EXTRACTION
    if bare['description']:
        LOG_DEBUG("descr.:\t" + bare['description'])  # DEBUG OUTPUT
        description = bare['description']
        db[url][3] = description
    
    # DATE EXTRACTION
    found_date = bare['date']
    if found_date:
        LOG('found date(s): ' + str(found_date))
        db[url][4] = found_date
    
    # CVE EXTRACTION
    found_cves = find_cves(main_body)
    if find_cves:
        LOG('Found CVE: ' + str(found_cves))
        db[url][5] = found_cves
    
    # NLP keyword generation
    # geting keywords: title
    if title:
        doc1 = nlp(title)
        db[url][9] = get_keywords(doc1)
    else:
        db[url][9] = None
    if bare['description']:
        doc2 = nlp(description)
        # geting keywords: description
        db[url][10] = get_keywords(doc2)
    else:
        db[url][10] = None
    if bare["text"]:
        doc3 = nlp(main_body)
        # geting keywords: text
        db[url][11] = get_keywords(doc3)
    else:
        db[url][12] = None

    # getting sentiment
    if do_senti:
        sentences = [i for i in nlp(main_body).sents]
        temp_senti = 0
        senti_scores = []
        for i in range(0, len(sentences)):
            LOG_DEBUG('curr_sentence: ')
            LOG_DEBUG(str(sentences[i]))
            try:
                temp_senti = helper_get_sentiment(sentences[i])
                senti_scores.append(temp_senti)
            except Exception as e:
                LOG('[-] - Error in calculating sentiment.' + str(e) + str(sentences[i]))
            LOG(temp_senti)
        db[url][7] = median(senti_scores)
    return(db)

# takes a URL and returns downloaded contents
def helper_fetch_html(url):
    downloaded = trafilatura.fetch_url(url)
    if downloaded == None:
        LOG('Error downloading page, trying reqests')
        downloaded = helper_fetch_requests(url)
        if downloaded == None:
            raise Exception('could not get page via requests, maybe unreachable')
        else:
            return downloaded
    return(downloaded)

# takes a URL and returns downloaded contents using the requests library
def helper_fetch_requests(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0'}
    try:
        r = requests.get(url, headers=headers)
    except Exception as e:
        print(e, 'could not fetch site via requests')
    else:
        html = r.text
        return str(BeautifulSoup(html, 'html.parser'))

# returns (sub)domain of given link
def helper_get_domain(link):
    return urlparse(link).netloc

# returns hash of given string
def helper_hash(string):
    return hashlib.sha256(string.encode('utf-8')).hexdigest()

# takes a string and returns a set of found CVEs
def find_cves(text):
    vces = set()
    if re.search('(?i)cve-\d{4}-\d{4,5}', text):
        vces.add(re.search('(?i)cve-\d{4}-\d{4,5}', text).group(0))
    return vces

# checks if all required directories are available. if not, creates them
def check_dirs():
    wkdir = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isdir(archive_path):
        LOG('Archive directory not present! Making one now!')
        os.makedirs(wkdir + '/' + archive_path)
    if not os.path.isdir(pdf_path):
        LOG('PDF directory not present! Making one now!')
        os.makedirs(wkdir + '/' + pdf_path)
    if not os.path.isdir(graph_path):
        LOG('Graph directory not present! Making one now!')
        os.makedirs(wkdir + '/' + graph_path)

# build a graph from db links with FULL FQDN
def build_graph_full(graph, db):
    for key in db.keys():
        graph.add_node(key)
        for found_link in db[key][0]:
            if args.db_only:
                if found_link in db.keys():
                    graph.add_edge(key, found_link)
            else:
                graph.add_edge(key, found_link)
    LOG('[graph] - Len Nodes: ' + str(len(graph.nodes.keys())))

# build graph from DOMAIN db links (for )
def build_graph_domain(graph, db):
    for key in db.keys():
        graph.add_node(helper_get_domain(key))
        for found_link in db[key][0]:
            if args.db_only:
                if found_link in db.keys():
                    graph.add_edge(helper_get_domain(key), helper_get_domain(found_link))
                else:
                    graph.add_edge(helper_get_domain(key), helper_get_domain(found_link))
    LOG('[graph] - Len Nodes: ' + str(len(graph.nodes.keys())))

# takes graph and gives dict of {link : pagerank} given amount of items
def get_graph_top(graph, n):
    if graph.nodes.keys():
        pageranged = pp.algorithms.centralities.pagerank(graph, alpha=0.85, max_iter=50, tol=1e-03, weighted=False)
        # return sorted(pageranged.items(), key=lambda x: x[1])[-n:]
        return pageranged
    else:
        return 'Nothing'

# draws graph with full URL
def draw_graph_full(graph, db):
    if graph:
        pageranged = pp.algorithms.centralities.pagerank(graph, alpha=0.85, max_iter=50, tol=1e-03, weighted=False)
        top = sorted(pageranged.items(), key=lambda x: x[1])[-3:]
        nodecolors = {}
        
        for key in db.keys():
            if key in graph.nodes.keys():
                nodecolors[key] = '#0008ff'

        for olink in original_links:
            nodecolors[olink] = '#0038ff'

        nodecolors[top[0][0]] = '#e5fc35'
        nodecolors[top[1][0]] = '#a6fc35'
        nodecolors[top[2][0]] = '#4ffc35'
        params = {'label_color': '#000000',
                    'node_color': nodecolors,
                    'height': '1300',
                    'width': '1500',
                    'node_text': pageranged}
        pp.visualisation.plot(graph, **params)
    else:
        LOG('[Err] - Empty graph. Cant return graph to html!')

# saves graph with domain only as node name
def save_graph_domain(graph, db):
    if graph.nodes:
        pageranged = pp.algorithms.centralities.pagerank(graph, alpha=0.85, max_iter=50, tol=1e-03, weighted=False)
        top = sorted(pageranged.items(), key=lambda x: x[1])[-3: ]
        nodecolors = {}
        for key in db.keys():
            nodecolors[helper_get_domain(key)] = '#1954a0'  # blue = in db
            
        for olink in original_links:
            if helper_get_domain(olink) in graph.nodes.keys():
                nodecolors[helper_get_domain(olink)] = '#19a08e' # türkis = origi

        nodecolors[top[0][0]] = '#e5fc35'
        nodecolors[top[1][0]] = '#a6fc35'
        nodecolors[top[2][0]] = '#4ffc35'
        params = {# 'label_color': '#000000',
                    'node_color': nodecolors,
                    'height':1300,
                    'width': 1500,
                    'node_size': 6.1,
                    'node_text': pageranged
                 }
        pp.visualisation.export_html(graph, graph_path+'graph.html', **params)
    else:
        LOG('[Err] - Empty graph. Cant save graph to html!')

# saves graph with full link name and no modifications
def save_graph_full_bare(graph, db):
    if graph.nodes:
        params = { 'height':1300, 'width': 1500}
        pp.visualisation.export_html(graph, graph_path+'graph.html', **params)
    else:
        LOG('[Err] - Empty graph. Cant save graph to html!')

# saves graph with full link name
def save_graph_full(graph, db):
    if graph.nodes:
        pageranged = pp.algorithms.centralities.pagerank(graph, alpha=0.85, max_iter=50, tol=1e-03, weighted=False)
        top = sorted(pageranged.items(), key=lambda x: x[1])[-3: ]
        nodecolors = {}
        for key in db.keys():
            nodecolors[key] = '#1954a0'  # blue = in db
            
        for olink in original_links:
            if olink in graph.nodes.keys():
                nodecolors[olink] = '#19a08e' # türkis = origi
            
        nodecolors[top[0][0]] = '#e5fc35'
        nodecolors[top[1][0]] = '#a6fc35'
        nodecolors[top[2][0]] = '#4ffc35'
        params = { 'label_color': '#000000',
                    'node_color': nodecolors,
                    'height':1300,
                    'width': 1500,
                    'node_size': 8.1,
                    'node_text': pageranged
                 }
        pp.visualisation.export_html(graph, graph_path+'graph.html', **params)
    else:
        LOG('[Err] - Empty graph. Cant save graph to html!')

# save pdfs from db and saved archive files. only run AFTER finished algo
def save_pdfs(db):
    LOG("Generating PDFs form archive files")
    # save PDF version of webpage if desired. Will load external content like pictures and so on. lots of log output.
    for url in db.keys():
        try:
            html_str = read_file(archive_path+helper_hash(url))
        except Exception as e:
            print(e, 'Error reading archived html file')

        pdfkit.from_string(html_str, pdf_path+helper_get_domain(url)+'.pdf', verbose=True)

# send a query to serpapi to get top 30 results. engines: duckduckgo, google
def query_to_engine(query, engine):
    new_links = set()
    if engine == '':
        engine = 'duckduckgo'
    url_base = 'https://serpapi.com/search.json?engine='+ engine +'&q='
    search_url = url_base + query + '&kl=wt-wt&api_key=' + serpapi_api_key
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0'}
    try:
        r = requests.get(search_url, headers=headers)
    except Exception as e:
        print(e, 'error fetching new links via serpapi '+ engine +' engine')
    data = r.json()  # this object contains position, title, link, snipped and favicon. Could be used for further analysis.

    print(data['organic_results'])
    for res in data['organic_results']:
        if sanitize_link(res['link']):
            new_links.add(res['link'])
    return new_links

# =========================================================================================================================================================
# NLP
# extract named entities from doc, returns ents object. Not used!
def helper_get_entities(doc):
    ents = {}
    # displacy.render(doc, style="ent") # RENDER ENTITIES IN TEXT
    for ent in doc.ents:
        ents[ent.text] = ent.label_
    return ents

# calculate sentiment of a given sentence
def helper_get_sentiment(text):
    s = flair.data.Sentence(str(text))
    flair_sentiment.predict(s)
    total_sentiment = s.labels[0]
    assert total_sentiment.value in ['POSITIVE', 'NEGATIVE']
    sign = 1 if total_sentiment.value == 'POSITIVE' else -1
    score = total_sentiment.score
    return sign * score

# returns percentage of matching keywords of two given keyword sets
def get_key_similarity(s1, s2):
    return get_percent(len(inters(s1, s2)), len(differ(s1, s2)))

# returns percentage of the two given input integers
def get_percent(first, second):
    return(first / second * 100)

# returns intersection of two sets
def inters(s1, s2):
    return(s1.intersection(s2))

# return symmertic difference of two sets
def differ(s1, s2):
    return(s1.symmetric_difference(s2))

# extracts keywords of a given nlp doc
def get_keywords(doc):
    keywords = set()
    for token in doc:
        if not token.is_stop and not token.is_punct and not token.is_oov and not token.is_digit:
            if token.pos_ != 'VERB' and token.pos_ != 'ADJ' and token.pos_ != 'ADV':
                keywords.add(token.lemma_)
    return(keywords)

# gets intersection of all elements of given db index
def get_intersection_db(db, index):
    intersection = None
    for key in db.keys():
        dbset = db[key][index]
        if dbset == '':
            continue
        if intersection is None:
            intersection = set(dbset)
            continue
        intersection = intersection.intersection(dbset)
    return intersection

# gets a set of all contents of given db index
def get_set_db(db, index):
    setdb = None
    for key in db.keys():
        if setdb is None:
            setdb = db[key][index]
            continue
        setdb.update(db[key][index])
    return setdb

# takes list of sentences(texts) and returns list of simitarities. first string against rest
def get_bert_similarities(sents):
    # loading deps here because its slow
    import numpy as np
    import torch
    from transformers import AutoTokenizer, AutoModel, logging
    from sklearn.metrics.pairwise import cosine_similarity
    logging.set_verbosity_error()
    tokenizer = AutoTokenizer.from_pretrained("jackaduma/SecRoBERTa")
    model = AutoModel.from_pretrained("jackaduma/SecRoBERTa")

    inputs = tokenizer(sents, padding=True, truncation=True, return_tensors="pt", max_length=(512))
    outputs = model(**inputs)
    embeddings = outputs.last_hidden_state
    attention_mask = inputs['attention_mask']                          # attention_mask is given by tokenizer!
    mask = attention_mask.unsqueeze(-1).expand(embeddings.size()).float()
    masked_embeddings = embeddings * mask
    summed = torch.sum(masked_embeddings, 1)
    summed_mask = torch.clamp(mask.sum(1), min=1e-9)
    mean_pooled = summed / summed_mask
    # convert from PyTorch tensor to numpy array
    mean_pooled = mean_pooled.detach().numpy()
    result = cosine_similarity([mean_pooled[0]], mean_pooled[1:])
    return result

# =========================================================================================================================================================
# Scraping
# parse all links found in the presented html form main body only
def helper_parsing_links(downloaded, url):
    LOG("Helper parsing: Start parsing for links")
    output=[]
    
    # -1) check for valid trafilatura output
    LOG("Checking if content is valid and usable with trafilatura (trafilatura: 1/3)")
    bare = trafilatura.bare_extraction(downloaded, include_comments=False, include_links=True, output_format='python')
    if bare['title']: LOG_DEBUG("title:\t" + bare['title'])  # DEBUG OUTPUT
    if bare['description']: LOG_DEBUG("descr.:\t" + bare['description'])  # DEBUG OUTPUT
    if bare["title"] == None:  # or bare["body"]:
        LOG("\t\tGot error in trafilatura. Trying to clean HTML..")
        downloaded_wo_unicode = unicodedata.normalize('NFKD', downloaded).encode('ascii', 'ignore')
        soup = BeautifulSoup(downloaded_wo_unicode, 'html.parser')
        downloaded = soup.prettify(formatter="html")
        LOG("Checking if content is valid and usable with trafilatura again")
        bare = trafilatura.bare_extraction(downloaded, include_comments=False, include_links=True, output_format='python')
        LOG_DEBUG(bare['title'])  # DEBUG OUTPUT
        LOG_DEBUG(bare['description'])  # DEBUG OUTPUT
    LOG("-> Got valid content")

    # 0) get links with trafilatura
    LOG_DEBUG("Trying to get links with trafilatura (trafilatura: 2/3)")

    my_xml = trafilatura.extract(downloaded, output_format='xml', include_comments=False, include_links=True)
    LOG_DEBUG("Extraction done with trafilatura. Starting to parse XML")
    tree=ET.fromstring(my_xml)
    subtree=tree.findall(".//ref[@target]")
    LOG_DEBUG("Got XML subtree with relevant links")
    all_links = list(map(lambda el: {"link text": el.text, "href": el.get('target')}, subtree))
    LOG_DEBUG("trafilatura links"); LOG_DEBUG(all_links)  # DEBUG OUTPUT
    for i in all_links:
        if not i["href"].startswith("#") and not i["href"].startswith("/") and not i['href'].startswith("javascript"):   # ignore local anchors
            if i["link text"]:
                output.append({"link text": i["link text"].strip().replace('\n', ' '), "href": i["href"]})    # add to output/return variable
            else:
                output.append({"link text": None, "href": i["href"]})    # add to output/return variable
    LOG("-> Done extracting links with trafilatura")

    # 1) get main body with trafilatura
    LOG_DEBUG("Trying to get main body with trafilatura (trafilatura: 3/3)")
    main_body_xml = trafilatura.extract(downloaded, output_format='xml', include_comments=False, include_links=False)
    tree=ET.fromstring(main_body_xml)
    main_body=' '.join(list(map(lambda el: str(ET.tostring(el).decode()).strip(), tree.findall(".//main/"))))
    LOG_DEBUG(main_body)
    LOG_DEBUG("-> Got main body with trafilatura (trafilatura: 3/3)")
    
    # 2) get all a href tag + word before from plain HTML
    LOG_DEBUG("Trying to extract href tag + word before from plain HTML")
    regex = r"([^\s<>]+)\s*?(?:<[^<]*?>\s*)*?<a\s+(?:[^>]*?\s+)?href=([\"'])([^\"']*?)\2[^>]*>(?:<[^<]*?>\s*)*(.+?)(?:<[^<]*?>\s*)*?</a>"
    matches = re.finditer(regex, downloaded, re.M)
    potential_urls=[]
    for matchNum, match in enumerate(matches, start=1):
        if not match.group(3).startswith("#") and not match.group(3).startswith("javascript") and not match.group(3).startswith("/"):     # ignore local anchors
            link_text =re.sub(re.compile('<.*?>'), '',  match.group(4))  # strip all html tags for match.group(4)
            potential_urls.append({"link text": link_text, "href": match.group(3), "word_before": match.group(1), "entire_html_code": match.group()})
    LOG_DEBUG("Potential links according to hrefs in HTML")
    LOG_DEBUG(potential_urls)
    LOG_DEBUG("-> Done extraction href tag + word before from plain HTML")
 
    # 3) match href tags with trafilatura-detected website content
    LOG_DEBUG("Trying to match href tags with trafilatura-detected website content")
    for u in potential_urls:
        LOG_DEBUG("Checking: " + u['href'] + " in main body")
        LOG_DEBUG(".. \"word before\" is " + u['word_before'])
        regex = re.escape(u['word_before'].strip())+r"\s*"+re.escape(u['link text'].strip())
        matches = re.finditer(regex, main_body)
        for matchNum, match in enumerate(matches, start=1):
            LOG("Found: " + u['href'] + " in main body")
            output.append({"link text": u['link text'].strip().replace('\n', ' '), "href": u['href']})
    LOG_DEBUG("-> Done matching href tags with trafilatura-detected website content")
    
    output = [dict(t) for t in {tuple(d.items()) for d in output}]     # remove duplicates (check name AND href!)
    LOG("Parsing done. Got " + str(len(output)) + " links")
    
    # remove same site urls
    for i in output:
        if helper_get_domain(i['href']) == helper_get_domain(url):
            LOG("Removing same domain url: " + str(i['href']))
            output.remove(i)
        if not 'http' in i['href']:
            LOG("Removing local url: " + str(i['href']))
            output.remove(i)

    return output

# fetch html with chrome stealth browser
def helper_fetch_html_chrome_headless(url):   
    LOG_DEBUG("-------------------------------------------------------------------------------")
    async def run_chrome(url):
        LOG_DEBUG("Starting headless chrome browser...")
        browser = await launch(headless=True)
        page = await browser.newPage()

        await stealth(page)  # <-- Here
        await page.goto(url, {'waitUntil' : 'networkidle0'})

        # click on twitter "Accept all cookies"
        if url.startswith("https://twitter.com"):
            LOG_DEBUG("Try to click on _Accept all cookies_")
            start = process_time()
            btn = []
            while len(btn) == 0:
                elapsed = process_time() - start
                if elapsed > 0.10:
                  break  # timeout 10s
                btn = await page.xpath('//span[contains(., "Accept all cookies")]')
                # btn = await page.xpath('/html/body/div[1]/div/div/div[1]/div/div[2]/div/div/div/div[2]/div[1]/div/span/span')
                sleep(1)
            for i in btn:
                try:
                  await i.click()
                except:
                  print("")
            LOG_DEBUG("Clicked...")

        content = await page.content()  # evaluate('document.body.textContent', force_expr=True)
        LOG('Got content with headless browser')
        LOG_DEBUG(content)
        # await page.screenshot({'path': 'example.png'})
        await browser.close()
        return(content)

    nest_asyncio.apply()
    content = asyncio.get_event_loop().run_until_complete(run_chrome(url))
    content = re.sub(r'<span\s+aria-hidden=\"true\"[^>]*>…</span>', '', content)    # Fix aria-hidden for twitter links
    content = re.sub(r'<span\s+aria-hidden=\"true\"[^>]*>([^<]+)</span>', r'\1', content)
    content = re.sub(r'…', '', content)
    LOG("Done headless browser crawling")

    return(content)

# =========================================================================================================================================================

# save file given filename and content
def save_file(filename, file):
    f = open(filename, "w")
    f.write(file)
    f.close()

# read file given path
def read_file(filename):
    f = open(filename, "r")
    file = f.read()
    f.close()
    return file

# read file and return list of lines of the file
def readlines_file(filename):
    f = open(filename, "r")
    file = f.readlines()
    f.close()
    return file

# parse file for input links, ignore comments, return list of lines of file
def get_input_file(path):
    lines = []
    for line in readlines_file(path):
        if helper_get_domain(line) != '' and line[:1] != '#':
            lines.append(line.strip())
    return lines

# takes a string and returns list of links or query (asks for confirmation if query; no links)
def get_input_string(str):
    outq = []
    if helper_get_domain(str) != '':
        outq.append(str)                                                                                    # ======== split TODO
        return outq
    else:
        answ = input('[-] - No links found!\n[?] - Is this a query? Type [y,n]: ' + str + '\n')
        if answ == 'y' or answ == 'Y':
            return query_to_engine(str, 'duckduckgo')
        else:
            print('[-] - EXITING NOW')
            exit()

# removes links if they match works from the exclusion list, returns link if ok, else False
def sanitize_link(pot_link):
    for i in exclusion_list:
        if i in pot_link:
            LOG('dropping link trough exclusion: ' + pot_link)
            return None
        else:
            LOG('[+] - Adding new link: ' + pot_link)
            return pot_link

# fill queue with links from db. returns new queue
def reseed_queue_db(db):
    temp_q = []
    for key in db.keys():
        for found_link in db[key][0]:
            # SANITAZE LINKS LIKE FACEBOOOK AND YOUTUBE AND CO; local links, ....
            if sanitize_link(found_link):
                temp_q.append(found_link)
    return temp_q

# dump db to cvs (for evaluating, graphing)
# [source] 0:set(found_links), 1:title, 2:text, 3:description, 4:date, 5:set(CVEs), 6:int(similarity to 1 link), 7:NLP_seintiment, 8: suggested_queries..
# 9: set:title-keywords, 10: set:desc-keywords, 11: set:text-keywords
def dump_db(db):
    out_csv = ''
    #out_names_str = 'original_link, ' + str(len(found_links) + ', ' + date + ', ' + str(cves) + ', ' + str(similarity_to_n0) + ', ' + str(sentiment)
    out_head = 'index, original_link, len(found_links), date, cves, similarity_to_n0, sentiment, pagerank \n'
    out_csv = out_head
    for i, key in enumerate(db.keys()):
        out_csv += str(i) + ', ' + str(key) + ', ' + str(len(db[key][0])) + ', ' + str(db[key][4]) + ', ' + str(db[key][5]) + ', ' + str(db[key][6]) + ', ' + str (db[key][7]) + ', ' + str(get_graph_top(graph, len(db.keys()))[key]) + '\n'
    #out_csv = pd.DataFrame(out_csv)
    # transpose 
    #out_csv = pd.out_csv.transpose()
    # saving the dataframe 
    # out_csv.to_csv('db.csv')
    save_file('db.csv', out_csv)
    print('saved csv')

# experimental export function
def dump_db2(db):
    
    row = [
        'index',
        'original_link',
        'len(found_links)',
        'date',
        'cves',
        'similarity_to_n0',
        'sentiment',
        'pagerank'
    ]
    '''
    'index' -> i form ennumerate
    'original_link' -> db.key
    'len(found_links)' -> len(v[0])
    'date' -> v[4]
    'cves' -> v[5]
    'similarity_to_n0' -> v[6]
    'sentiment' -> v[7]
    'pagerank' -> TODO
    '''
    w.writerow(row)
    for i, (k, v) in enumerate(db.items()):
        pagerank = 'TODO'
        row = [i, k, len(v[0])] + [v[j] for j in [4, 5, 6, 7]] + get_graph_top(graph, len(db.keys()))[key]
        w.writerow(row)
    save_file('db.csv', out_csv)
    print('saved csv')

# =========================================================================================================================================================

# to be moved to seperated branch
# starts flask http API
def start_api(port):
    from flask import Flask, request
    app = Flask(__name__)


    @app.route('/')
    def home():
        return 'Welcome to ldig.', 200

    @app.route('/query', methods=['GET'])
    def api_from_query():
        new_query = request.args.get('q')
        # do ldig query call
        return {'input': new_query, 'output': 'TBD'}, 200

    @app.route('/links', methods=['GET'])
    def api_from_link():
        new_links = request.args.get('q')
        # do ldig queue call
        return {'response': new_links}, 200


    # all non-existing routes will return a 404 error
    @app.errorhandler(404)
    def not_found(e):
        return {'response': 'Not found!'}, 404


    # start the webserver
    if __name__ == '__main__':
        LOG('[+] - Starting API')
        app.run(debug=False, host='0.0.0.0', port=port)
         
# ========

# parse commandline arguments
parser = argparse.ArgumentParser()
parser.add_argument('-I', '--infile')                           # input links via file
parser.add_argument('-i', '--instring')                         # input links via string stdin

# parser.add_argument('-A', '--api_port')                       # any port above 20'000, for V2

parser.add_argument('-t', '--nlp_threshold', type=float)        # float input to set threshold for NLP similarity checks
parser.add_argument('-e', '--search_engine')                    # google or duckduckgo
parser.add_argument('-l', '--layer_depth', type=int)            # link digging depth
parser.add_argument('-s', '--sentiment', action="store_true")   # sentiment calculations and output
parser.add_argument('-g', '--graph', action="store_true")       # graph output
parser.add_argument('-d', '--db_only', action="store_true")     # don't graph links that are not in db
parser.add_argument('-p', '--pdf', action="store_true")         # PDF output
parser.add_argument('-f', '--force', action="store_true")       # force redownload all links (ignore cache)
parser.add_argument('-x', '--db_export', action="store_true")   # Export DB switch
parser.add_argument('-v', '--verbose', action="store_true")     # LOG output
parser.add_argument('-vv', '--vverbose', action="store_true")   # Debug LOG output
args = parser.parse_args()
if not args.instring and not args.infile:
    parser.error('No input links provided.')
# initial dataobjects generation
graph = pp.Network(directed=True)
queue = []
original_links = []
db = {}


DISABLE_LOGS()
if args.verbose:
    ENABLE_LOGS()
if args.vverbose:
    ENABLE_DEBUG()



# verify infile is a file or directory
if args.infile != None and not os.path.isdir(args.infile) and not os.path.isfile(args.infile):
    raise argparse.ArgumentTypeError('%s is not a valid file or directory' % args.infile)

# if infile is file
if args.infile != None and os.path.isfile(args.infile):
    queue = get_input_file(args.infile)

# if instring is given but not a file
if args.instring != None and not os.path.isfile(args.instring):
    queue = get_input_string(args.instring)

# save original sources for comparison later
if queue:
    original_links = queue.copy()
    LOG_DEBUG('ORIGINAL LINKS: ' + str(original_links))

# do sentiment output
if args.sentiment:
    do_senti = True
    import flair
    flair_sentiment = flair.models.TextClassifier.load('en-sentiment')
else:
    do_senti = False

# For V2 (seperate branch)
# if args.api_port:
#     start_api(args.api_port)
# ========

while queue != None and len(queue) != 0:
    LOG('[+] Processing Queue Item Nr. ' + str(len(queue)))
    url = queue.pop(0)
    try:
        db = get_all_contents(url, db)
    except Exception as e:
        print(e, '[-] - Error getting contents in main loop')

    if not queue and args.search_engine:
        LOG('[+] - intersection of all text-keywords: ' + str(list(get_intersection_db(db, 11))))
        LOG('[+] - set of all title-keywords: ' + str(list(get_set_db(db, 9))))
        LOG('[+] - Keywords inters of both = search query generation: ' + str(get_intersection_db(db, 11).intersection(get_set_db(db, 9))))
        # getting the intersection of all text-intersections and a set of all words of all texts as new query to links as queue
        queue = list(query_to_engine(str(get_intersection_db(db, 11).intersection(get_set_db(db, 9))), args.search_engine))
        #LOG('NEW QUEUE from '+ args.search_engine + str(queue))
        args.search_engine = None

        # TEMP for manual testing
        #queue = get_input_file('testing_data/EX1_LI4_hpilobleed_serpapi_only.txt')
        #queue = get_input_file('testing_data/EX2_LI3_log3shell_serpapi_only.txt')
        #queue = get_input_file('testing_data/EX3_LI3_doorlock_serpapi_only.txt')


    if not queue and original_links != list(db.keys()) and len(db.keys()) > 1:
        LOG('[NLP] - Prepairing and processing data to clean db')
        nlp_input_dict = {}
        nlp_links = []
        nlp_texts = []
        not_relevant_links = []

        # get all texts from db
        for key in db.keys():
            if db[key][2] != None:
                LOG('[+] - Prepairing key; text' + key + '; \t' + db[key][2][:50])
                nlp_links.append(key)
                nlp_texts.append(db[key][2])

        # takes only first 512 words per text! first item against all others. gives list of similarities to each tiem without the first one the is being compared against
        result = get_bert_similarities(nlp_texts)
        for x in range(len(result[0])+1):
            a = result[0]
            if x == 0:
                LOG('[NLP] - Comparison String: ' + nlp_links[x] + '\t' + nlp_texts[x][0:50])
                continue
            LOG(str(x) + ': ' + str(a[x-1]) + "\t" + nlp_links[x][0:50])
            
            # save similarity to db
            if nlp_links[x] in db.keys():
                db[nlp_links[x]][6] = a[x-1]

            # similarity default = 0.72; REMOVE db itmes if link below threshold
            if args.nlp_threshold:
                threshold = args.nlp_threshold
            else:
                threshold = 0.72
            if a[x-1] < threshold:
                LOG_DEBUG(str(x) + ' TO BE REMOVED: ' + str(a[x-1]) + "\t" + nlp_links[x][0:50])
                not_relevant_links.append(nlp_links[x])

        # remove not relevant links and data from db
        for link in not_relevant_links:
            if link in original_links:
                LOG('[!] - Attention, text similatiry of original link is below ' + str(threshold) + ' for link: ' +  link + '\n[+] - NOT REMOVING LINK')
                continue
            db.pop(link)
            LOG('[-] - Link similarity below Threshold of ' + str(threshold) + ' - DELETED LINK FROM DB: ' + link[:50]) # also need to delete link form link sets in db items TODO==========

    elif not queue and original_links == list(db.keys()):
        LOG('[NLP] - No new data found. Nothing to process.')

    if not queue and args.layer_depth:
            queue = reseed_queue_db(db)
            args.layer_depth -= 1

# print found keywords
if db:
    # GRAPH build
    build_graph_full(graph, db)
    # GRAPH export
    if args.graph:
        save_graph_full(graph, db)
    # Export database if -x flag is set
    if args.db_export:
    	dump_db(db) # db export for data analysis
    # PDF export
    if args.pdf:
        save_pdf = True  # generates a lot of warn and error log in stdout
        save_pdfs(db)
    # print alll found CVEs
    if get_set_db(db, 5):
        print('[=] FINISHED. CVE(s) found: ', get_set_db(db, 5))

    print('[=] - Text Keywords: ' + str(get_intersection_db(db, 11)))
    print('[=] - Title Keywords: ' + str(get_set_db(db, 9)))
    print('[=] - Keywords: ' + str(get_intersection_db(db, 11).intersection(get_set_db(db, 9))))
    # print final summary
    if do_senti:
        print('[=] ', 'Simil.', '\t', 'Pagerank Score', '\t','Sentiment Score','\t', 'URL', '\t\t\t\t', 'New Links', '\t' ,'Date','\t\t', 'Title', '\t\t\t', 'Description', '\t\t', 'Text')
        for key in db.keys():
            print('[=] ', round(db[key][6], 4), '\t', get_graph_top(graph, len(db.keys()))[key], '\t', db[key][7], '\t' , key[:28] ,'\t', len(db[key][0]),'\t\t', db[key][4], '\t', db[key][1][:20], '\t', db[key][2][:20], '\t', db[key][2][:20])
        print('[=] Most probable source (pagerank winner): ', sorted(get_graph_top(graph, 1).items(), key=lambda x: x[1])[-1:])
    else:
        print('[=] ', 'Simil.', '\t', 'Pagerank Score','\t', 'URL', '\t\t\t\t', 'New Links', '\t' ,'Date','\t\t', 'Title', '\t\t\t', 'Description', '\t\t', 'Text')
        for key in db.keys():
            print('[=] ', round(db[key][6], 4), '\t', get_graph_top(graph, len(db.keys()))[key], '\t', key[:28],'\t', len(db[key][0]),'\t\t', db[key][4], '\t', db[key][1][:20], '\t', db[key][2][:20], '\t', db[key][2][:20])
        print('[=] Most probable source (pagerank winner): ', sorted(get_graph_top(graph, 1).items(), key=lambda x: x[1])[-1:])
