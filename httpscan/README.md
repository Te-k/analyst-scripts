# HTTP Scanner

## HOWTO

## Phhshing kit fingerprint

### Example

```
$ python httpscan.py -s example.com -F
Fingerprinting example.com
    -> match on examplesig
```

### Signature format

Signature uses YAML format and are close to yara signature, tests and condition

Example:
```yaml
---
examplesig:
    tests:
        - name: index
        path: index.html
        code: 200
        content: "<body>"
    condition: all
```

Tests should contains name and path and at least one of the following criteria:
* Code : HTTP return code
* content : look for content

Condition can be "any" or "all"


## HTTP Fingerprint notes

### Header field ordering

nginx:
```
Server: nginx
Date: Sat, 21 Jan 2017 03:57:35 GMT
Content-Type: text/html
Last-Modified: Sun, 02 Oct 2016 05:00:32 GMT
Transfer-Encoding: chunked
Connection: keep-alive
Content-Encoding: gzip

```
