# ldig - Link Digger

This application scrapes cyber security related news articles and returns potenial sources. It compares articles with natural language processing to identify how relevant they are. It can also generate Keywords to query a searchengine for more related links. The source is finally determined via the pagerank algorithm of a directed graph that represents the relations of all links to each other.

Input a link as string or a file with links to start.

## Requirements
The host should at least have the following system resouces:
- 20 Gb ram
- 4 CPUs
- 20 GB Free Space (for NLP Data and new Data)

## Installation

```
sudo apt update
sudo apt install python3-pip
pip install trafilatura flair argparse pdfkit flask pathpy bs4 pandas numpy torch spacy nest_asyncio transformers sklearn
python3 -m spacy download en_core_web_lg
```
The following packages are required to run this application:
### NLP models

- [jackaduma/SecRoBERTa](https://github.com/jackaduma/SecBERT)
- [spacy-models/en_core_web_lg3.3.0](https://github.com/explosion/spacy-models/releases/tag/en_core_web_lg-3.3.0)
- [flair/sentiment-en-mix-distillbert_4](https://nlp.informatik.hu-berlin.de/resources/models/sentiment-curated-distilbert/)

The models should get downloaded automatically during first operation.

## Usage
```txt
python3 ldig.py [-h] [-I INFILE] [-i INSTRING] [-t NLP_THRESHOLD] [-e SEARCH_ENGINE] [-l LAYER_DEPTH] [-s] [-g] [-d] [-p] [-f] [-x] [-v] [-vv]

-h  Help
-I  Textfile with links without delimiter
-i  Inputstring: link or query
-t  NLP treshold in float. 0.4 = 40% similarity retention
-e  Searchengine to reseed queue with fresh links
-l  How many layers of found links should be crawled.
-s  Calculate sentiment analysis of all texts
-g  Save a html graph animation of all links
-d  Render only links with metadata in the DB to the output graph
-p  Save a PDF for each downloaded link
-f  Force download links even if the are cached
-x  Export DB after successful run for plotting
-v  Verbose LOG to STDOUT
-vv Verbose DEBUG LOG to STDOUT
```

### Example

```bash
python3 ldig.py -h
python3 ldig.py -l 0 -i https://www.cnbc.com/2021/03/09/microsoft-exchange-hack-explained.html
python3 ldig.py -i https://www.cnbc.com/2021/03/09/microsoft-exchange-hack-explained.html
```

### Configuratoion file
Things like savelocations or API-keys can be configured in the configuration file `conf/conf.py`

## Example

Input a file with links to articles (-I). Also reseed queue with new links via a given searchengine (-e). Scrape all the unresolved links once (-l). Output as graph.html (-g).

`python3 ldig.py -g -I input/some_articles.txt -e duckduckgo -l 1`


## Why do I exist? What is my purpose?
This project was developed as part of a bachelors thesis in information and cyber security.

## Aknowlegements

This project is built upon existing frameworks and libraries:
- [Trafilatura](https://github.com/adbar/trafilatura)
- [PyTorch](https://github.com/pytorch/pytorch)
- [Transformers](https://github.com/huggingface/transformers)
- [Sklearn](https://github.com/scikit-learn/scikit-learn)
- [Pathpy](https://www.pathpy.net)
- [Beautifulsoup 4](https://pypi.org/project/beautifulsoup4/)
- [flair](https://github.com/flairNLP/flair)
- [spacy](https://spacy.io)
- [pdfkit](https://pypi.org/project/pdfkit/)
