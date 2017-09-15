# Googl URL shortener tools

Tool to get information about goo.gl shortened urls through the API. To create a key, check [here](https://developers.google.com/url-shortener/v1/getting_started#APIKey). Works in python 2 and python 3.

Key should be stored in `~/.goo.gl`:
```
[API]
key: KEYHERE
```

**Help** :
```bash
$ python api.py -h
usage: api.py [-h] [--hash HASH] [--file FILE]

Check goo.gl infos through the API

optional arguments:
  -h, --help            show this help message and exit
  --hash HASH, -H HASH  HASH of a link
  --file FILE, -f FILE  Get hashes from a file
```

**Check a hash**:
```bash
$ python api.py -H fbsS
{
    "analytics":{
        "allTime":{
            "browsers":[
                {
                    "count":"6607390",
                    "id":"Chrome"
                },
[SNIP]
    "created":"2009-12-13T07:22:55.000+00:00",
    "id":"http://goo.gl/fbsS",
    "kind":"urlshortener#url",
    "longUrl":"http://www.google.com/",
    "status":"OK"
}
```
