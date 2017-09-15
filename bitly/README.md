# Bitly

Tool to request the Bitly API (see documentation [here](https://dev.bitly.com/api.html)). Works with python 2 and python 3.

## Configuration

Configuration information should be stored in `~/.bitly`:
```
[General]
token: TOKEN
```

## As CLI

**Help**
```
$ python bitly.py -h
usage: bitly.py [-h] [--hash HASH] [--file FILE] [-v]

Check bit.ly infos through the API

optional arguments:
  -h, --help            show this help message and exit
  --hash HASH, -H HASH  HASH of a link
  --file FILE, -f FILE  File containing list of hashes
  -v, --verbose
```

**Check a hash information**
```
$ python bitly.py -H chauncey
-------------------- Bit.ly Link infos -------------------
# INFO
Link: http://bit.ly/chauncey		Metrics: http://bit.ly/chauncey+
Expanded url: http://www.cutestdogcompetition.com/vote.cfm?h=AF23DA2F9B1C92EFA53494BC892C7955
Creation Date: 2009-08-05 15:58:20
Aggregate link: http://bit.ly/1J44jq
1 bitly redirect to this url

# LINK  INFO
indexed: 0
aggregate_link: http://bit.ly/1J44jq
original_url: http://www.cutestdogcompetition.com/vote.cfm?h=AF23DA2F9B1C92EFA53494BC892C7955
canonical_url: http://www.cutestdogcompetition.com/vote.cfm?h=AF23DA2F9B1C92EFA53494BC892C7955
error: Crawl restricted by robots.txt

# USERS
User: jweln
Invalid user!

# CLICKS
182 clicks on this link

# COUNTRIES
-US: 142 clicks
-CN: 26 clicks
-FR: 3 clicks
-CA: 3 clicks
-GB: 2 clicks
-SE: 2 clicks
-UA: 1 clicks
-IT: 1 clicks
-IN: 1 clicks
-MY: 1 clicks

# REFERRERS
-direct: 78 clicks
-http://www.facebook.com/home.php: 71 clicks
-http://twitter.com/: 6 clicks
-http://www.facebook.com/holmespi: 5 clicks
-http://www.facebook.com/profile.php: 3 clicks
-http://m.facebook.com/home.php: 2 clicks
-http://www.facebook.com/reqs.php: 2 clicks
-http://www.facebook.com/s.php: 1 clicks
-http://1167.xg4ken.com/pages/chauncey: 1 clicks
-http://www.facebook.com/search/: 1 clicks
-http://1154.xg4ken.com/pages/chauncey: 1 clicks
-http://www.facebook.com/posted.php: 1 clicks
-http://powertwitter.me/: 1 clicks
-http://www.facebook.com/TraceyBroadhurst: 1 clicks
-http://www.plaxo.com/events: 1 clicks
-http://www.facebook.com/lafilmgirl: 1 clicks
-http://www.facebook.com/aaron.j.moses: 1 clicks
-http://www.facebook.com/find-friends/index.php: 1 clicks
-http://www.facebook.com/inbox/readmessage.php: 1 clicks
-http://www.facebook.com/album.php: 1 clicks
-http://www.facebook.com/Thinkingcaps: 1 clicks
-http://twitter.com/HolmesPI: 1 clicks
```

**Check hashes in a file**:
```
$ python -i bitly.py -f urls
Date;Short URL;Long URL;Analytics;Aggregate;Aggregate Hash;User;Short URL Clicks;Long URL Clicks
07/03/2012 18:45:29;http://bit.ly/LNY08h;http://blog.bitly.com/post/26449494972/happy-independence-day-america;http://bit.ly/LNY08h+;LNY08h;Yes;LNY08h;636;636
08/05/2009 15:58:20;http://bit.ly/chauncey;http://www.cutestdogcompetition.com/vote.cfm?h=AF23DA2F9B1C92EFA53494BC892C7955;http://bit.ly/chauncey+;1J44jq;No;jweln;182;182
```

## Use as a library

The code of the tool should be pretty straightforward:
```python
bitly = Bitly(access_token=TOKEN)
link = Link(bitly, HASH)
print(link.long_url)
print(link.clicks)
```





