import argparse
import os
import sys
import re
import base64
from email.header import decode_header
import email
from lxml import html
import quopri


def decode_html(body, quoted=True):
    """
    Extract links and images from html
    """
    if quoted:
        tree = html.fromstring(quopri.decodestring(body))
    else:
        tree = html.fromstring(body)
    links = set(tree.xpath("//a/@href"))
    images = set(tree.xpath("//img/@src"))
    print("Links:")
    for a in links:
        print(a)
    print("")
    print("Images:")
    for a in images:
        print(a)


def decode_plain(body, quoted=True):
    if quoted:
        body = quopri.decodestring(body)
    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
    if len(urls) > 0:
        print("Urls:")
        for u in set(urls):
            print(u)
    else:
        print("No urls identified")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract attached files from an eml file')
    parser.add_argument('EMAIL', help='EML file')
    parser.add_argument('--dump', '-D', action='store_true', help='Dump attachments')
    parser.add_argument('--show', '-s', type=int, help='Show one object')
    args = parser.parse_args()


    if not os.path.isfile(args.EMAIL):
        print("Invalid file path")
        sys.exit(1)

    with open(args.EMAIL, 'rb') as ff:
        raw_email = ff.read()

    msg = email.message_from_bytes(raw_email)

    print("==== Headers")
    print("From: {}".format(msg['From']))
    print("To: {}".format(msg['To']))
    if msg['Subject'].startswith("=?"):
        h = decode_header(msg['Subject'])
        print("Subject: {}".format(h[0][0].decode(h[0][1])))
    else:
        print("Subject: {}".format(msg['Subject']))
    print("Date: {}".format(msg["Date"]))
    if msg["Reply(To"]:
        print("Reply-To: {}".format(msg["Reply-To"]))
    if msg.is_multipart():
        print("Multipart Email")
    print("")
    if msg.is_multipart():
        for p in msg.get_payload():
            print("==== Part")
            print("Type: {}".format(p.get_content_type()))
            if p.get_content_type() == "text/plain":
                content = p.get_payload(decode=True).decode(p.get_content_charset())
                decode_plain(content, quoted=False)
            elif p.get_content_type() == "text/html":
                content = p.get_payload(decode=True)
                decode_html(content)
            else:
                # TODO : attached files
                print("Content type not analyzed")
            print("")
    else:
        body = msg.get_payload()
        ptype = msg["Content-Type"]
        if "text/html" in ptype:
            decode_html(body)
        elif "text/plain" in ptype:
            decode_plain(body)



