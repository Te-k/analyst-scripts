import argparse
import os
import sys
import base64
from email.header import decode_header


def parse_eml(data):
    """
    Parse the content of an eml file
    """
    lines = data.split('\n')
    l = 0
    res = []
    _count = 0
    while l < len(lines):
        if lines[l].startswith('----') and not lines[l].strip().endswith('--'):
            # New something
            # Get the type and encoding
            _id = lines[l].strip('-')
            _type = None
            _charset = None
            _encoding = None
            _attachment = False
            _filename = None
            l += 1
            # Parse header
            while lines[l].strip() != '':
                if lines[l].startswith('Content-Type'):
                    _type = lines[l][14:].split(';')[0]
                    if 'charset=' in lines[l]:
                        _charset = lines[l][lines[l].find('charset=')+8:]
                if lines[l].startswith('Content-Transfer-Encoding'):
                    _encoding = lines[l][26:].strip()
                if lines[l].startswith('Content-Disposition: attachment'):
                    _attachment = True
                    _filename = lines[l][lines[l].find('filename=')+10:].strip('"')
                    if _filename.startswith('=?'):
                        # Encoded filename
                        a = decode_header(_filename)
                        _filename = "".join(list(map(lambda x: x[0].decode(x[1]), a)))
                l += 1
            while lines[l].strip() == '':
                l += 1

            # Parse content
            content = ''
            if not lines[l].startswith('----'):
                while lines[l].strip() != '' and not lines[l].startswith('----'):
                    content += lines[l].strip()
                    l += 1

            a = {"type": _type, "id": _id, "attachment": _attachment, "count": _count, "content": content}
            if _charset:
                a["charset"] = _charset
            if _encoding:
                a["encoding"] = _encoding
            if _filename:
                a["filename"] = _filename
            if _encoding == 'base64':
                if _charset:
                    a['decoded'] =  base64.b64decode(content).decode(_charset)
                else:
                    a['decoded'] =  base64.b64decode(content)
            res.append(a)
            _count += 1
        else:
            l += 1
    return res


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract attached files from an eml file')
    parser.add_argument('EMAIL', help='EML file')
    parser.add_argument('--dump', '-D', action='store_true', help='Dump attachments')
    parser.add_argument('--show', '-s', type=int, help='Show one object')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose mode')
    args = parser.parse_args()


    if not os.path.isfile(args.EMAIL):
        print("Invalid file path")
        sys.exit(1)

    ff = open(args.EMAIL, 'r')
    res = parse_eml(ff.read())

    if args.dump:
        _count = 0
        if len([r for r in res if r['attachment']]) == 0:
            print("No attachments in this email")
        else:
            for r in res:
                if r['attachment']:
                    with open('attachment{}'.format(_count), 'wb+') as f:
                        f.write(r['decoded'])
                    print("Attachment {} ({}) written in attachment{}".format(_count, r['filename'], _count))
                _count += 1
    elif args.show is not None:
        if args.show > len(res) -1:
            print("This object does not exist")
        else:
            r = res[args.show]
            print("Type: {}".format(r['type']))
            print("id: {}".format(r['id']))

            if r['attachment']:
                print("Attachment named {}".format(r['filename']))
                print("{} bytes".format(len(r['decoded'])))
            else:
                if 'decoded' in r:
                    print(r['decoded'])
                else:
                    print(r['content'])
    else:
        for r in res:
            if r['type'] == 'multipart/alternative':
                continue
            else:
                print('-----------------------------------------------')
                if r['attachment']:
                    print('{} - Attachment {}'.format(r['count'], r['filename']))
                    print('{} bytes'.format(len(r['decoded'])))
                else:
                    print('{} - {}'.format(r['count'], r['type']))
                    if 'decoded' in r:
                        print(r['decoded'])
                    else:
                        print(r['content'])
                print()
