# analyst-scripts : MISP scripts

Scripts for using MISP

* misp.py : copy of [Nicolas Bareil python-misp library](https://github.com/nbareil/python-misp)
* mispcli.py : Command line interface for MISP
* mispcopy.py : script to copy attributes from one event to another

## Configuration

All these scripts uses the same configuration file which should be in ~/.misp with the following format:
```
[Server1]
url: URL
key: key
default: true

[Server2]
url: url
key: key
```

## mispcli

List events:
```bash
# python mispcli.py -l
1 - Event with stuff in it
2 - another event
...
```

Information about an event:
```
$ python mispcli.py -e 42
Event 42 : Title
Tags : TLP:RED
10 Attributes including:
    - 1 comment (0 for detection)
    - 7 domain (7 for detection)
    - 1 hostname (1 for detection)
    - 1 ip-dst (1 for detection)

```

Disable for IDS all the md5 in event 48 from Server2:
```
$ python mispcli.py -s server2 -e 48 -t md5 --no-ids
Attr df85d882ac37e278c9995dbbbfae7173 already not for IDS detection
Attr 044eadff537f21814b923291f9614cab already not for IDS detection
Attr 21a1ee58e4b543d7f2fa3b4022506029 already not for IDS detection
Attr 36d2f0228c1c4f60bd1dad94977e5a5a already not for IDS detection
Attr 1088a1d71916c674daae730642d77eda already not for IDS detection
Attr 5cea24fb20763d255c67efe2b3fc9cc6 already not for IDS detection
Attr 46d030b4253fa7911c3748f04420d1c4 already not for IDS detection
Attr 7a368bf665bf601b679d079bea2923ae already not for IDS detection
Attr 9ef1fadd764489b4161cce4a43929f9f already not for IDS detection
Attr a13af624b690e1ead49bdf0d24560654 already not for IDS detection
...
```

### mispcopy

Simple script to copy IOCs from an event to another:
```
usage: mispcopy.py [-h] [--no-cleaning]
                   SERVER_SOURCE EVENT_SOURCE SERVER_DEST EVENT_DEST

Command line interface to MISP servers

positional arguments:
  SERVER_SOURCE      Server source for the copy
  EVENT_SOURCE       Event source
  SERVER_DEST        Server destination
  EVENT_DEST         Event destination

optional arguments:
  -h, --help         show this help message and exit
  --no-cleaning, -c  Do not clean attributes (personal rules)
```

Example:
```
$ python mispcopy.py server1 41 server2 468
Uploaded Network activity  / domain / www.google.com
...
```

