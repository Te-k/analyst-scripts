import os
import sys
import argparse
import collections
from zipfile import ZipFile
from lxml import etree
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML, FileOpenError

"""
Script analyzing docx files
https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/multi-stage-email-word-attack-without-macros/
https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/
"""


def extract_targets(input_zip):
    """
    Extract rel targets
    """
    res = []
    for n in input_zip.namelist():
        if n.endswith('.rels'):
            data = input_zip.read(n)
            root = etree.fromstring(data)
            if root.tag == "{http://schemas.openxmlformats.org/package/2006/relationships}Relationships":
                for c in root.getchildren():
                    if c.tag == "{http://schemas.openxmlformats.org/package/2006/relationships}Relationship":
                        if c.get('Target'):
                            res.append([c.get('Type').split('/')[6], c.get('Target')])
            else:
                print("Malformed rels file {}, weird".format(n))
    return res


def extract_metadata(input_zip):
    """
    Extract metadata information
    """
    res = []
    if 'docProps/core.xml' in input_zip.namelist():
        data = input_zip.read('docProps/core.xml')
        root = etree.fromstring(data)
        if not root.tag.endswith('coreProperties'):
            print("Impossible to extract metadata")
        else:
            for c in root.getchildren():
                res.append([c.tag.split('}')[1], c.text])

    return res


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Analyze docx document (pretty limited for now)')
    parser.add_argument('FILE', help='Docx document')
    args = parser.parse_args()

    if not os.path.isfile(args.FILE):
        print("Invalid file path")
        sys.exit(1)

    # Check if any macro and extract it
    try:
        vbaparser = VBA_Parser(args.FILE)
        if vbaparser.detect_vba_macros():
            print('VBA Macros found')
            mac_name = os.path.splitext(args.FILE)[0] + '.macro'
            with open(mac_name, 'w+') as f:
                for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                    f.write(vba_code)
                    f.write('\n')
            print("Macro dumped in {}".format(mac_name))
        else:
            print('No VBA Macros found')
    except FileOpenError:
        print("Failed to open file with olevba")

    # Show metadata
    input_zip = ZipFile(args.FILE)
    print("")
    print("Metadata:")
    for d in extract_metadata(input_zip):
        print("-{} : {}".format(*d))

    # Analyze types of files
    print("")
    print("Types of files:")
    for c in collections.Counter([os.path.splitext(a)[1] for a in input_zip.namelist()]).items():
        if c[0].strip() != '':
            print("-{}: {}".format(c[0], c[1]))


    # Check for "script" target exploiting CVE-2017-8570
    targets = extract_targets(input_zip)
    scripts = [a[0] for a in targets if a[0].strip().lower().startswith('script')]
    print("")
    if len(scripts) > 0:
        print("CVE-2017-8570 exploit identified: {}".format(','.join(scripts)))
    else:
        print("No script reference found (CVE-2017-8570)")

    # Search for oleObject in rels
    oleobjects = [a for a in targets if a[0].strip().lower() == 'oleobject']
    print("")
    if len(oleobjects) == 0:
        print("No oleObject found")
    else:
        print("OleObject found: {}".format(','.join([a[1] for a in oleobjects])))

    # TODO : add Video HTML https://blog.cymulate.com/abusing-microsoft-office-online-video

    # Print rels target urls
    print("")
    print("rel Targets urls:")
    for t in targets:
        if t[1].strip().lower().startswith('http') or t[1].strip().lower().startswith('file'):
            print("{} : {}".format(t[0], t[1]))
